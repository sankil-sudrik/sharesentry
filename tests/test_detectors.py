import unittest

from sharesentry.detectors import (
    attach_excerpts, detect, detect_api_keys, detect_cloud_keys, detect_credit_cards, detect_emails,
    detect_internal_labels, detect_phones, detect_private_keys, detect_user_terms, luhn_valid,
    mask_text, merge_overlapping,
)
from sharesentry.models import Category, Finding, Rule, Severity
from sharesentry.skills import SKILLS_BY_NAME, apply_skill
from sharesentry.models import Context
from tests.helpers import CARD, EMAIL, TOKEN


def spans(text, findings):
    return [text[f.start:f.end] for f in findings]


class EmailTests(unittest.TestCase):
    def test_finds_exact_span(self):
        text = f"write to {EMAIL}, thanks"
        self.assertEqual(spans(text, detect_emails(text)), [EMAIL])

    def test_plus_addressing_and_subdomains(self):
        text = "a.b+tag@mail.sub.example.org"
        self.assertEqual(spans(text, detect_emails(text)), [text])

    def test_ignores_non_emails(self):
        self.assertEqual(detect_emails("see @handle or user@ or a@b"), [])


class PhoneTests(unittest.TestCase):
    def test_formats_are_found_and_marked_uncertain(self):
        for number in ("+1 415 555 0134", "(415) 555-0134", "415-555-0134", "+91 98765 43210", "98765 43210"):
            found = detect_phones(f"call {number} today")
            self.assertEqual(len(found), 1, number)
            self.assertTrue(found[0].confidence.startswith("uncertain"))
            self.assertEqual(found[0].severity, Severity.MEDIUM)

    def test_ip_addresses_and_dates_are_not_phones(self):
        self.assertEqual(detect_phones("host 192.168.100.200 on 2026-10-29"), [])


class CreditCardTests(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertFalse(luhn_valid("4111111111111112"))
        self.assertFalse(luhn_valid("123"))

    def test_valid_card_found_invalid_ignored(self):
        text = f"card {CARD} and 4111 1111 1111 1112"
        found = detect_credit_cards(text)
        self.assertEqual(spans(text, found), [CARD])
        self.assertIn("Luhn", found[0].confidence)

    def test_dashes(self):
        self.assertEqual(len(detect_credit_cards("4111-1111-1111-1111")), 1)


class SecretTests(unittest.TestCase):
    def test_token_formats(self):
        samples = [TOKEN, "sk-ant-api03-" + "A" * 30, "ghp_" + "a" * 36, "xoxb-1234567890-abcdef", "nvapi-" + "B" * 30]
        for sample in samples:
            self.assertEqual(spans(sample, detect_api_keys(sample)), [sample], sample)

    def test_assignment_captures_value_only(self):
        text = 'password = "hunter2hunter2"'
        self.assertEqual(spans(text, detect_api_keys(text)), ["hunter2hunter2"])

    def test_bearer_token(self):
        text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"
        self.assertEqual(spans(text, detect_api_keys(text)), ["abcdefghijklmnopqrstuvwxyz012345"])

    def test_plain_words_are_not_keys(self):
        self.assertEqual(detect_api_keys("risk-based task-force sk-short"), [])

    def test_redaction_placeholders_are_not_flagged(self):
        self.assertEqual(detect("api_key = [REDACTED:API_KEY]"), [])

    def test_private_key_block_and_header_only(self):
        block = "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE\n-----END RSA PRIVATE KEY-----"
        found = detect_private_keys(f"x {block} y")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        header_only = detect_private_keys("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
        self.assertEqual(len(header_only), 1)
        self.assertIn("header only", header_only[0].confidence)

    def test_aws_keys(self):
        text = "id AKIAIOSFODNN7EXAMPLE secret aws_secret_access_key=" + "A" * 40
        found = detect_cloud_keys(text)
        self.assertEqual(len(found), 2)
        self.assertTrue(all(f.severity == Severity.CRITICAL for f in found))


class LabelAndTermTests(unittest.TestCase):
    def test_internal_labels(self):
        text = "CONFIDENTIAL draft. Internal use only. Do not distribute."
        self.assertEqual(len(detect_internal_labels(text)), 3)

    def test_user_terms_whole_word_case_insensitive(self):
        rule = Rule("r1", "Codename", "", Severity.HIGH, terms=["Project Bluefin"], action="Rename")
        text = "project bluefin and PROJECT BLUEFIN but not Project Bluefinch"
        found = detect_user_terms(text, [rule])
        self.assertEqual(len(found), 2)
        self.assertEqual({f.rule_id for f in found}, {"r1"})
        self.assertEqual(found[0].suggested_action, "Rename")

    def test_short_or_blank_terms_ignored(self):
        rule = Rule("r1", "x", "", Severity.LOW, terms=["", " ", "a"])
        self.assertEqual(detect_user_terms("a a a", [rule]), [])


class MergeAndMaskTests(unittest.TestCase):
    def finding(self, start, end, category=Category.EMAIL, severity=Severity.LOW):
        return Finding("", category, severity, start, end, "r", "c", "a")

    def test_overlaps_become_one_union_named_by_most_severe(self):
        merged = merge_overlapping([self.finding(0, 10), self.finding(5, 20, Category.API_KEY, Severity.HIGH), self.finding(30, 40)])
        self.assertEqual([(f.start, f.end, f.category) for f in merged], [(0, 20, Category.API_KEY), (30, 40, Category.EMAIL)])

    def test_adjacent_spans_stay_separate(self):
        self.assertEqual(len(merge_overlapping([self.finding(0, 5), self.finding(5, 9)])), 2)

    def test_mask_text_and_excerpts_never_contain_raw_values(self):
        text = f"mail {EMAIL} token {TOKEN} end"
        findings = merge_overlapping(detect(text))
        masked = attach_excerpts(text, findings)
        self.assertNotIn(EMAIL, masked)
        self.assertNotIn(TOKEN, masked)
        for f in findings:
            self.assertNotIn("example-client", f.masked_excerpt)
            self.assertNotIn("FAKE000", f.masked_excerpt)
        self.assertIn("[EMAIL]", masked)

    def test_mask_spans_point_at_labels(self):
        text = f"a {EMAIL} b"
        findings = merge_overlapping(detect(text))
        masked, spans_ = mask_text(text, findings)
        start, end = spans_[0]
        self.assertEqual(masked[start:end], "[EMAIL]")


class SkillTests(unittest.TestCase):
    TEXT = f"{EMAIL} CONFIDENTIAL {TOKEN}"

    def scan(self, skill_name, context=Context.EXTERNAL_CLIENT):
        skill = SKILLS_BY_NAME[skill_name]
        findings = merge_overlapping(detect(self.TEXT, skill.categories))
        apply_skill(findings, skill, context)
        return {f.category: f.severity for f in findings}

    def test_skills_change_which_detectors_run(self):
        self.assertEqual(set(self.scan("Secrets & Credentials Scan")), {Category.API_KEY})
        self.assertIn(Category.EMAIL, self.scan("Client-Ready Review"))

    def test_skills_change_severity(self):
        self.assertEqual(self.scan("Client-Ready Review")[Category.EMAIL], Severity.MEDIUM)
        self.assertEqual(self.scan("Public Release Review")[Category.EMAIL], Severity.HIGH)
        self.assertEqual(self.scan("Secrets & Credentials Scan")[Category.API_KEY], Severity.CRITICAL)

    def test_internal_team_context_relaxes_labels_but_not_secrets(self):
        external = self.scan("Public Release Review", Context.EXTERNAL_CLIENT)
        internal = self.scan("Public Release Review", Context.INTERNAL_TEAM)
        self.assertEqual(internal[Category.INTERNAL_LABEL], external[Category.INTERNAL_LABEL].lowered())
        self.assertEqual(internal[Category.API_KEY], external[Category.API_KEY])


if __name__ == "__main__":
    unittest.main()
