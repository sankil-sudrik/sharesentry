import json
import tempfile
import unittest
from pathlib import Path

from sharesentry.audit import csv_column_summary, determine_status, run_audit
from sharesentry.config import PROVIDERS, load_settings
from sharesentry.models import Audit, Context, Finding, Category, Rule, Severity, Status
from sharesentry.report import report_dict, report_json, report_markdown
from sharesentry.sample import SAMPLE_RULES, load_sample, sample_files
from sharesentry.skills import SKILLS, SKILLS_BY_NAME
from sharesentry.store import AuthError, Workspace, workspace_path
from tests.helpers import EMAIL, TOKEN, make_pdf, parse

CLIENT = SKILLS_BY_NAME["Client-Ready Review"]


def finding(severity):
    return Finding("F1", Category.EMAIL, severity, 0, 1, "r", "c", "a")


class StatusTests(unittest.TestCase):
    def test_status_rules(self):
        self.assertEqual(determine_status([finding(Severity.CRITICAL)], []), Status.ACTION_REQUIRED)
        self.assertEqual(determine_status([finding(Severity.HIGH)], ["x"]), Status.ACTION_REQUIRED)
        self.assertEqual(determine_status([finding(Severity.LOW)], []), Status.REVIEW_RECOMMENDED)
        self.assertEqual(determine_status([], []), Status.NO_ISSUES)
        self.assertEqual(determine_status([], ["scanned page"]), Status.INCOMPLETE)

    def test_scanned_pdf_is_incomplete_never_clean(self):
        audit = run_audit(parse("a.pdf", make_pdf(["", ""])), CLIENT, Context.EXTERNAL_CLIENT)
        self.assertEqual(audit.status, Status.INCOMPLETE)
        self.assertEqual(audit.findings, [])

    def test_partly_scanned_pdf_without_findings_is_incomplete(self):
        audit = run_audit(parse("a.pdf", make_pdf(["clean text", ""])), CLIENT, Context.EXTERNAL_CLIENT)
        self.assertEqual(audit.status, Status.INCOMPLETE)

    def test_partly_scanned_pdf_with_findings_still_reports_them(self):
        audit = run_audit(parse("a.pdf", make_pdf([f"key {TOKEN}", ""])), CLIENT, Context.EXTERNAL_CLIENT)
        self.assertEqual(audit.status, Status.ACTION_REQUIRED)
        self.assertTrue(audit.incomplete_reasons)

    def test_csv_skill_on_non_csv_adds_scope_note(self):
        audit = run_audit(parse("a.txt", b"hello"), SKILLS_BY_NAME["CSV Data Minimizer"], Context.EXTERNAL_CLIENT)
        self.assertTrue(any("designed for CSV" in n for n in audit.scope_notes))


class SampleAuditTests(unittest.TestCase):
    def test_sample_text_triggers_every_detector_category(self):
        audit = run_audit(load_sample(), CLIENT, Context.EXTERNAL_CLIENT, SAMPLE_RULES)
        found = {f.category for f in audit.findings}
        self.assertEqual(found, {c for c in Category if c is not Category.AI_CONCERN})
        self.assertEqual(audit.status, Status.ACTION_REQUIRED)
        self.assertTrue(audit.count(Severity.CRITICAL) >= 2)

    def test_finding_ids_are_unique_and_sequential(self):
        audit = run_audit(load_sample(), CLIENT, Context.EXTERNAL_CLIENT, SAMPLE_RULES)
        ids = [f.finding_id for f in audit.findings]
        self.assertEqual(ids, [f"F{i:03d}" for i in range(1, len(ids) + 1)])

    def test_disabled_or_out_of_context_rules_do_not_fire(self):
        rule = Rule("r", "Codename", "", Severity.HIGH, terms=["Project Bluefin"], contexts=[Context.PUBLIC_RELEASE])
        audit = run_audit(load_sample(), CLIENT, Context.EXTERNAL_CLIENT, [rule])
        self.assertNotIn(Category.USER_TERM, {f.category for f in audit.findings})
        rule.contexts, rule.enabled = [], False
        audit = run_audit(load_sample(), CLIENT, Context.EXTERNAL_CLIENT, [rule])
        self.assertNotIn(Category.USER_TERM, {f.category for f in audit.findings})

    def test_csv_sample_column_summary(self):
        doc = load_sample("synthetic_clients.csv")
        audit = run_audit(doc, SKILLS_BY_NAME["CSV Data Minimizer"], Context.EXTERNAL_CLIENT)
        names = {row["name"]: row["findings"] for row in csv_column_summary(doc, audit.findings)}
        self.assertEqual(names["contact_email"], 3)
        self.assertEqual(names["phone"], 2)
        self.assertEqual(names["notes"], 1)
        self.assertEqual(csv_column_summary(load_sample(), audit.findings), [])

    def test_all_sample_files_exist_and_parse(self):
        for name in sample_files():
            self.assertTrue(load_sample(name).inspectable, name)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.audit = run_audit(load_sample(), CLIENT, Context.EXTERNAL_CLIENT, SAMPLE_RULES)

    def test_reports_never_contain_raw_values(self):
        for output in (report_json(self.audit), report_markdown(self.audit)):
            for secret in ("jordan.rivera", "4111 1111", "sk-FAKE", "AKIAIOSFODNN7", "MIIFAKE", "415 555"):
                self.assertNotIn(secret, output)

    def test_report_json_round_trips_and_carries_disclaimer(self):
        data = json.loads(report_json(self.audit))
        self.assertIn("not a guarantee", data["disclaimer"])
        self.assertEqual(Audit.from_dict(data).audit_id, self.audit.audit_id)
        self.assertEqual(data["counts"]["critical"], self.audit.count(Severity.CRITICAL))
        self.assertEqual(report_dict(self.audit)["tool"]["name"], "ShareSentry")

    def test_markdown_lists_scope_limits_and_ai_status(self):
        text = report_markdown(self.audit)
        self.assertIn("AI review:** skipped", text)
        self.assertIn("## Findings", text)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_create_open_and_wrong_passphrase(self):
        Workspace.create(self.dir, "Team-A", "correct horse")
        Workspace.open(self.dir, "team-a", "correct horse")
        with self.assertRaises(AuthError):
            Workspace.open(self.dir, "team-a", "wrong passphrase")
        with self.assertRaises(AuthError):
            Workspace.open(self.dir, "nobody", "correct horse")

    def test_validation(self):
        with self.assertRaises(ValueError):
            Workspace.create(self.dir, "ok", "short")
        with self.assertRaises(ValueError):
            workspace_path(self.dir, "../escape")
        Workspace.create(self.dir, "ok", "long enough")
        with self.assertRaises(ValueError):
            Workspace.create(self.dir, "ok", "long enough")

    def test_passphrase_is_hashed_not_stored(self):
        ws = Workspace.create(self.dir, "ok", "very-secret-pass")
        self.assertNotIn(b"very-secret-pass", ws.path.read_bytes())

    def test_workspaces_are_isolated(self):
        a = Workspace.create(self.dir, "a", "passphrase-a")
        b = Workspace.create(self.dir, "b", "passphrase-b")
        a.save_rule(Rule("r1", "Only A", "", Severity.LOW, terms=["x1"]))
        self.assertEqual([r.rule_id for r in a.list_rules()], ["r1"])
        self.assertEqual(b.list_rules(), [])

    def test_rules_crud_and_persistence_across_reopen(self):
        ws = Workspace.create(self.dir, "w", "passphrase-1")
        rule = Rule("r1", "Codename", "desc", Severity.HIGH, terms=["Bluefin"], contexts=[Context.EXTERNAL_CLIENT])
        ws.save_rule(rule)
        rule.enabled = False
        ws.save_rule(rule)
        reopened = Workspace.open(self.dir, "w", "passphrase-1")
        loaded = reopened.list_rules()
        self.assertEqual((len(loaded), loaded[0].enabled, loaded[0].contexts), (1, False, [Context.EXTERNAL_CLIENT]))
        reopened.delete_rule("r1")
        self.assertEqual(reopened.list_rules(), [])

    def test_skill_toggles(self):
        ws = Workspace.create(self.dir, "w", "passphrase-1")
        self.assertTrue(all(ws.skill_states().values()))
        self.assertEqual(set(ws.skill_states()), {s.name for s in SKILLS})
        ws.set_skill_enabled("Client-Ready Review", False)
        self.assertFalse(ws.skill_states()["Client-Ready Review"])

    def test_audit_history_stores_masked_data_only(self):
        ws = Workspace.create(self.dir, "w", "passphrase-1")
        audit = run_audit(load_sample(), CLIENT, Context.EXTERNAL_CLIENT, SAMPLE_RULES)
        ws.save_audit(audit)
        raw = ws.path.read_bytes()
        for secret in (b"jordan.rivera", b"sk-FAKE", b"AKIAIOSFODNN7", b"4111 1111"):
            self.assertNotIn(secret, raw)
        loaded = ws.get_audit(audit.audit_id)
        self.assertEqual(loaded.to_dict(), audit.to_dict())
        self.assertEqual([a.audit_id for a in ws.list_audits()], [audit.audit_id])
        ws.delete_audit(audit.audit_id)
        self.assertIsNone(ws.get_audit(audit.audit_id))

    def test_backup_export_import_round_trip_without_credentials(self):
        source = Workspace.create(self.dir, "src", "passphrase-src")
        source.save_rule(Rule("r1", "Codename", "d", Severity.HIGH, terms=["Bluefin"]))
        source.set_skill_enabled("Public Release Review", False)
        source.save_audit(run_audit(load_sample(), CLIENT, Context.EXTERNAL_CLIENT))
        backup = source.export_backup()
        blob = json.dumps(backup)
        self.assertNotIn("passphrase-src", blob)
        self.assertNotIn("salt", blob)
        self.assertEqual(json.loads(json.dumps(source.export_backup(include_terms=False)))["rules"][0]["terms"], [])
        target = Workspace.create(self.dir, "dst", "passphrase-dst")
        self.assertEqual(target.import_backup(json.loads(blob)), {"rules": 1, "audits": 1, "skills": len(SKILLS)})
        self.assertEqual(target.list_rules()[0].terms, ["Bluefin"])
        self.assertFalse(target.skill_states()["Public Release Review"])

    def test_bad_backups_are_rejected_before_writing(self):
        ws = Workspace.create(self.dir, "w", "passphrase-1")
        for bad in ({}, {"backup_version": 99}, {"backup_version": 1, "rules": [{"nope": 1}]}, "text"):
            with self.assertRaises(ValueError):
                ws.import_backup(bad)
        self.assertEqual(ws.list_rules(), [])

    def test_delete_removes_the_file(self):
        ws = Workspace.create(self.dir, "w", "passphrase-1")
        ws.delete()
        self.assertFalse(Workspace.exists(self.dir, "w"))


class ConfigTests(unittest.TestCase):
    def test_defaults_use_nemotron_super_on_nvidia(self):
        ai = load_settings({}).ai
        self.assertEqual(ai.provider, "nvidia")
        self.assertEqual(ai.model, "nvidia/nemotron-3-super-120b-a12b")
        self.assertTrue(ai.is_nemotron)
        self.assertFalse(ai.configured)

    def test_provider_presets_and_overrides(self):
        for key, provider in PROVIDERS.items():
            if key != "custom":
                ai = load_settings({"AI_PROVIDER": key, "AI_API_KEY": "k"}).ai
                self.assertEqual((ai.base_url, ai.model, ai.configured), (provider.base_url, provider.default_model, True))
        groq = load_settings({"AI_PROVIDER": "groq", "AI_API_KEY": "k"}).ai
        self.assertFalse(groq.is_nemotron)  # the UI warns when the model is not Nemotron
        custom = load_settings({"AI_PROVIDER": "custom", "AI_BASE_URL": "http://h/v1/", "AI_MODEL": "m", "AI_API_KEY": "k"}).ai
        self.assertEqual((custom.base_url, custom.model), ("http://h/v1", "m"))

    def test_invalid_values_raise_clear_errors(self):
        for env in ({"AI_PROVIDER": "bogus"}, {"AI_TIMEOUT_SECONDS": "abc"}, {"SHARESENTRY_MAX_UPLOAD_MB": "0"}):
            with self.assertRaises(ValueError):
                load_settings(env)

    def test_limits(self):
        settings = load_settings({"SHARESENTRY_MAX_UPLOAD_MB": "2", "AI_MAX_INPUT_CHARS": "100"})
        self.assertEqual((settings.max_upload_bytes, settings.ai.max_input_chars), (2 * 1024 * 1024, 100))


if __name__ == "__main__":
    unittest.main()
