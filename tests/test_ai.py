import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from sharesentry import ai
from sharesentry.audit import run_audit
from sharesentry.config import AIConfig
from sharesentry.models import Category, Context, Source, Status
from sharesentry.skills import SKILLS_BY_NAME
from tests.helpers import EMAIL, TOKEN, parse

SKILL = SKILLS_BY_NAME["Client-Ready Review"]
CONFIG = AIConfig(api_key="test-key", base_url="http://example.invalid/v1", model="nvidia/nemotron-test")
TEXT = f"Mail {EMAIL}. Our internal margin is 42 percent. key {TOKEN}"


class Recorder:
    def __init__(self, content):
        self.content, self.calls = content, []

    def __call__(self, method, url, payload, headers, timeout):
        self.calls.append((method, url, payload, headers, timeout))
        return {"choices": [{"message": {"content": self.content}}]}


def run(content, text=TEXT, **overrides):
    recorder = Recorder(content)
    audit = run_audit(parse("a.txt", text.encode()), SKILL, Context.EXTERNAL_CLIENT, ai_config=CONFIG, use_ai=True, transport=recorder, **overrides)
    return audit, recorder


class AnalyzeGatingTests(unittest.TestCase):
    def test_no_consent_means_no_request(self):
        recorder = Recorder("{}")
        result = ai.analyze(CONFIG, "x", [], Context.EXTERNAL_CLIENT, "", [], consent=False, transport=recorder)
        self.assertEqual(result.outcome.status, "skipped")
        self.assertEqual(recorder.calls, [])

    def test_unconfigured_endpoint_is_skipped_with_reason(self):
        recorder = Recorder("{}")
        result = ai.analyze(AIConfig(), "x", [], Context.EXTERNAL_CLIENT, "", [], consent=True, transport=recorder)
        self.assertEqual(result.outcome.status, "skipped")
        self.assertIn("no API key", result.outcome.message)
        self.assertEqual(recorder.calls, [])

    def test_audit_without_use_ai_never_calls_the_model(self):
        recorder = Recorder("{}")
        audit = run_audit(parse("a.txt", TEXT.encode()), SKILL, Context.EXTERNAL_CLIENT, ai_config=CONFIG, use_ai=False, transport=recorder)
        self.assertEqual(recorder.calls, [])
        self.assertEqual(audit.ai.status, "skipped")


class RequestContentTests(unittest.TestCase):
    def test_request_is_bounded_and_contains_no_raw_values(self):
        audit, recorder = run('{"summary": "ok"}')
        method, url, payload, headers, timeout = recorder.calls[0]
        body = json.dumps(payload)
        self.assertEqual((method, url), ("POST", "http://example.invalid/v1/chat/completions"))
        self.assertEqual(payload["model"], "nvidia/nemotron-test")
        self.assertEqual((payload["max_tokens"], payload["temperature"], timeout), (900, 0, 45.0))
        self.assertEqual(headers["Authorization"], "Bearer test-key")
        for secret in (EMAIL, TOKEN, "example-client"):
            self.assertNotIn(secret, body)
        self.assertIn("[EMAIL]", body)
        self.assertEqual(len(recorder.calls), 1)

    def test_rule_terms_are_never_sent(self):
        from sharesentry.models import Rule, Severity
        rule = Rule("r", "Codename policy", "Keep codenames private", Severity.HIGH, terms=["Bluefin"])
        recorder = Recorder("{}")
        run_audit(parse("a.txt", b"Project Bluefin is here"), SKILL, Context.EXTERNAL_CLIENT, [rule], CONFIG, True, recorder)
        body = json.dumps(recorder.calls[0][2])
        self.assertNotIn("Bluefin", body)
        self.assertIn("Codename policy", body)

    def test_long_input_is_truncated_and_disclosed(self):
        config = AIConfig(api_key="k", base_url="http://x/v1", model="m", max_input_chars=50)
        recorder = Recorder('{"summary": "ok"}')
        audit = run_audit(parse("a.txt", ("word " * 100).encode()), SKILL, Context.EXTERNAL_CLIENT, ai_config=config, use_ai=True, transport=recorder)
        self.assertTrue(audit.ai.truncated)
        self.assertIn("first 50 characters", audit.ai.message)
        self.assertLessEqual(len(recorder.calls[0][2]["messages"][1]["content"].split("(masked) ---\n")[1]), 50)


class ResponseHandlingTests(unittest.TestCase):
    def payload(self, **parts):
        return json.dumps({"summary": "Pricing is exposed.", **parts})

    def test_valid_response_adds_located_concern_and_notes(self):
        content = self.payload(
            assessments=[{"finding_id": "F001", "relevance": "confirmed", "rationale": "real address"}],
            additional_concerns=[{"quote": "Our internal margin is 42 percent", "reason": "internal pricing", "severity": "high"}],
        )
        audit, _ = run(content)
        self.assertEqual(audit.ai.status, "succeeded")
        self.assertEqual(audit.ai.summary, "Pricing is exposed.")
        self.assertTrue(audit.findings[0].ai_note.startswith("AI: confirmed"))
        concern = [f for f in audit.findings if f.category == Category.AI_CONCERN][0]
        self.assertEqual(concern.source, Source.AI)
        self.assertTrue(concern.located)
        self.assertEqual(TEXT[concern.start:concern.end], "Our internal margin is 42 percent")

    def test_think_blocks_and_code_fences_are_tolerated(self):
        audit, _ = run("<think>hmm</think>\n```json\n" + self.payload() + "\n```")
        self.assertEqual(audit.ai.status, "succeeded")

    def test_hallucinated_quote_is_discarded(self):
        audit, _ = run(self.payload(additional_concerns=[{"quote": "text that is not in the document", "reason": "x", "severity": "high"}]))
        self.assertFalse([f for f in audit.findings if f.category == Category.AI_CONCERN])

    def test_quote_with_placeholder_or_unknown_finding_ids_are_ignored(self):
        audit, _ = run(self.payload(
            assessments=[{"finding_id": "F999", "relevance": "confirmed", "rationale": "x"}, {"finding_id": "F001", "relevance": "bogus", "rationale": "x"}],
            additional_concerns=[{"quote": "Mail [EMAIL]", "reason": "x", "severity": "low"}],
        ))
        self.assertTrue(all(not f.ai_note for f in audit.findings))
        self.assertFalse([f for f in audit.findings if f.category == Category.AI_CONCERN])

    def test_ambiguous_quote_becomes_unlocated_review_item(self):
        audit, _ = run(self.payload(additional_concerns=[{"quote": "repeat repeat", "reason": "x", "severity": "low"}]), text="repeat repeat and repeat repeat")
        concern = audit.findings[0]
        self.assertFalse(concern.located)
        self.assertEqual(audit.status, Status.REVIEW_RECOMMENDED)

    def test_model_cannot_create_critical_findings(self):
        audit, _ = run(self.payload(additional_concerns=[{"quote": "Our internal margin", "reason": "x", "severity": "critical"}]))
        concern = [f for f in audit.findings if f.category == Category.AI_CONCERN][0]
        self.assertEqual(concern.severity.name, "MEDIUM")

    def test_ai_can_never_clear_deterministic_findings_or_declare_safe(self):
        content = self.payload(assessments=[{"finding_id": "F001", "relevance": "unlikely", "rationale": "harmless"}])
        audit, _ = run(content)
        self.assertEqual(audit.status, Status.ACTION_REQUIRED)
        self.assertGreaterEqual(len(audit.findings), 2)

    def test_ai_only_concern_on_clean_document_still_requires_review(self):
        text = "We will undercut the rival by ten percent."
        audit, _ = run(self.payload(additional_concerns=[{"quote": "undercut the rival", "reason": "strategy", "severity": "medium"}]), text=text)
        self.assertEqual(audit.status, Status.REVIEW_RECOMMENDED)

    def test_clean_document_with_empty_ai_reply_is_not_called_safe(self):
        audit, _ = run(self.payload(), text="Nothing here.")
        self.assertEqual(audit.status, Status.NO_ISSUES)
        self.assertIn("within scope", audit.status.label)
        self.assertNotIn("safe", audit.status.label.lower())


class FailureHandlingTests(unittest.TestCase):
    def test_invalid_json_and_wrong_shapes_fail_cleanly(self):
        for content in ("not json at all", "[1, 2]", "{broken", None):
            audit, _ = run(content)
            self.assertEqual(audit.ai.status, "failed", content)
            self.assertEqual(audit.status, Status.ACTION_REQUIRED)  # deterministic result survives

    def test_unexpected_response_shape(self):
        audit = run_audit(parse("a.txt", TEXT.encode()), SKILL, Context.EXTERNAL_CLIENT, ai_config=CONFIG, use_ai=True, transport=lambda *a: {"oops": 1})
        self.assertEqual(audit.ai.status, "failed")

    def test_transport_errors_become_failed_outcomes(self):
        def boom(*args):
            raise ai.AIError("The endpoint could not be reached (network error or timeout).")
        audit = run_audit(parse("a.txt", TEXT.encode()), SKILL, Context.EXTERNAL_CLIENT, ai_config=CONFIG, use_ai=True, transport=boom)
        self.assertEqual(audit.ai.status, "failed")
        self.assertIn("could not be reached", audit.ai.message)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(200, {"data": [{"id": "nvidia/nemotron-3-super-120b-a12b"}, {"id": "other/model"}]})

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length))
        if self.headers["Authorization"] != "Bearer good":
            return self._send(401, {"error": "no"})
        self._send(200, {"choices": [{"message": {"content": json.dumps({"summary": "served " + body["model"]})}}]})


class HttpTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_real_http_round_trip_and_model_listing(self):
        config = AIConfig(api_key="good", base_url=self.base, model="nvidia/nemotron-x")
        audit = run_audit(parse("a.txt", b"hello"), SKILL, Context.EXTERNAL_CLIENT, ai_config=config, use_ai=True)
        self.assertEqual(audit.ai.status, "succeeded")
        self.assertEqual(audit.ai.summary, "served nvidia/nemotron-x")
        self.assertIn("nvidia/nemotron-3-super-120b-a12b", ai.list_models(config))

    def test_http_error_is_reported_without_leaking_the_key(self):
        config = AIConfig(api_key="bad-key-123", base_url=self.base, model="m")
        audit = run_audit(parse("a.txt", b"hello"), SKILL, Context.EXTERNAL_CLIENT, ai_config=config, use_ai=True)
        self.assertEqual(audit.ai.status, "failed")
        self.assertIn("HTTP 401", audit.ai.message)
        self.assertNotIn("bad-key-123", audit.ai.message)

    def test_unreachable_endpoint(self):
        config = AIConfig(api_key="k", base_url="http://127.0.0.1:9/v1", model="m", timeout_seconds=2)
        audit = run_audit(parse("a.txt", b"hello"), SKILL, Context.EXTERNAL_CLIENT, ai_config=config, use_ai=True)
        self.assertEqual(audit.ai.status, "failed")

    def test_list_models_requires_configuration(self):
        with self.assertRaises(ai.AIError):
            ai.list_models(AIConfig())


if __name__ == "__main__":
    unittest.main()
