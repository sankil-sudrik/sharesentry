"""Drives the real app.py through its pages using the fake Streamlit module."""

import json
import os
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sharesentry.models import Severity
from sharesentry.store import Workspace
from tests.fake_streamlit import FakeStreamlit, FakeUpload, Rerun
from tests.helpers import EMAIL

APP = Path(__file__).resolve().parent.parent / "app.py"


class AppTestCase(unittest.TestCase):
    ENV = {}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        env = {"SHARESENTRY_DATA_DIR": self._tmp.name, "AI_API_KEY": "", **self.ENV}
        patches = [mock.patch.dict(os.environ, env), mock.patch.dict(sys.modules, {"streamlit": (st := FakeStreamlit())})]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.st = st

    def run_app(self, *clicked, **values):
        """Run the script once per user action; button clicks only apply to the first pass."""
        self.st.clicked, self.st.values = set(clicked), {**self.st.values, **values}
        self.st.calls.clear()
        for _ in range(5):
            try:
                runpy.run_path(str(APP), run_name="__main__")
                return
            except Rerun:
                self.st.clicked = set()
        self.fail("app kept rerunning")

    def login(self):
        self.run_app("Create new", Workspace="Create new", **{"Workspace name": "demo", "Passphrase": "passphrase-1"})
        self.assertIn("workspace", self.st.session_state)


class LoginTests(AppTestCase):
    def test_login_screen_then_create_and_open(self):
        self.run_app()
        self.assertTrue(self.st.called("title", "ShareSentry"))
        self.login()
        self.assertTrue(self.st.called("header", "New audit"))
        self.st.session_state.clear()
        self.run_app("Open existing", Workspace="Open existing", **{"Workspace name": "demo", "Passphrase": "passphrase-1"})
        self.assertIn("workspace", self.st.session_state)

    def test_wrong_passphrase_and_bad_input_show_errors(self):
        self.login()
        self.st.session_state.clear()
        self.run_app("Open existing", Workspace="Open existing", **{"Workspace name": "demo", "Passphrase": "nope-nope"})
        self.assertIn("wrong passphrase", " ".join(self.st.messages("error")))
        self.run_app("Create new", Workspace="Create new", **{"Workspace name": "x", "Passphrase": "short"})
        self.assertIn("at least 8", " ".join(self.st.messages("error")))

    def test_bad_configuration_is_reported_not_crashed(self):
        with mock.patch.dict(os.environ, {"AI_PROVIDER": "bogus"}):
            self.run_app()
        self.assertIn("Configuration error", self.st.messages("error")[0])


class AuditFlowTests(AppTestCase):
    def test_sample_audit_redaction_and_downloads(self):
        self.login()
        self.run_app("Run on synthetic sample")
        self.assertIn("Action required", self.st.messages("error"))
        self.assertTrue(self.st.called("dataframe"))
        self.assertTrue(self.st.called("download_button", "Download report (JSON)"))
        self.assertEqual(len(self.st.called("metric")), 4)

        self.run_app("Generate redacted copy")
        self.assertTrue(any("no findings remain" in m for m in self.st.messages("success")))
        download = self.st.called("download_button", "Download redacted copy")[0][1]
        self.assertNotIn(b"sk-FAKE", download[1])
        self.assertEqual(download[2], "redacted_synthetic_sample.txt")

        ws = self.st.session_state["workspace"]
        saved = ws.list_audits()
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0].verification.clean)

    def test_upload_audit_for_each_format_without_ai(self):
        self.login()
        self.run_app("Run audit", Document=FakeUpload("note.txt", f"hello {EMAIL}".encode()))
        self.assertIn("Review recommended", self.st.messages("warning"))  # one email = Medium under Client-Ready
        self.run_app("Run audit", Document=FakeUpload("bad.exe", b"MZ"))
        self.assertTrue(any("Not inspected" in m for m in self.st.messages("warning")))

    def test_run_without_file_asks_for_one(self):
        self.login()
        self.run_app("Run audit")
        self.assertIn("Choose a document first.", self.st.messages("error"))

    def test_csv_minimizer_offers_column_removal(self):
        self.login()
        self.run_app("Run on synthetic sample", Skill="CSV Data Minimizer")
        self.assertTrue(self.st.called("multiselect", "Columns to remove entirely"))
        self.run_app("Generate redacted copy", **{"Columns to remove entirely": [1]})
        out = self.st.called("download_button", "Download redacted copy")[0][1][1].decode()
        self.assertNotIn("contact_email", out)
        self.assertIn("client,phone,notes", out)


class OtherPagesTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_rules_add_toggle_delete_backup(self):
        form = {"Name": "Codename", "What it protects": "keep private", "Terms (one per line)": "Bluefin\nOrion"}
        self.run_app("Add rule", Navigate="Rules & Memory", **form)
        ws = self.st.session_state["workspace"]
        rules = ws.list_rules()
        self.assertEqual((len(rules), rules[0].terms, rules[0].severity), (1, ["Bluefin", "Orion"], Severity.HIGH))
        self.run_app(Navigate="Rules & Memory")
        self.assertTrue(self.st.called("download_button", "Export workspace backup"))
        backup = json.loads(self.st.called("download_button", "Export workspace backup")[0][1][1])
        self.assertEqual(backup["rules"][0]["name"], "Codename")
        self.run_app("Delete rule", Navigate="Rules & Memory")
        self.assertEqual(ws.list_rules(), [])

    def test_rule_validation(self):
        self.run_app("Add rule", Navigate="Rules & Memory", Name="", **{"Terms (one per line)": ""})
        self.assertIn("A rule needs a name and at least one term.", self.st.messages("error"))

    def test_restore_backup_and_invalid_backup(self):
        ws = self.st.session_state["workspace"]
        good = {"backup_version": 1, "rules": [{"rule_id": "r1", "name": "N", "severity": "low", "terms": ["zz"]}]}
        self.run_app("Import backup", Navigate="Rules & Memory", **{"Restore from backup": FakeUpload("b.json", json.dumps(good).encode())})
        self.assertEqual([r.rule_id for r in ws.list_rules()], ["r1"])
        self.run_app("Import backup", Navigate="Rules & Memory", **{"Restore from backup": FakeUpload("b.json", b'{"backup_version": 7}')})
        self.assertTrue(self.st.messages("error"))

    def test_skills_toggle_hides_skill_from_audit(self):
        ws = self.st.session_state["workspace"]
        self.run_app(Navigate="Skills", **{"Enabled": False})
        self.assertFalse(any(ws.skill_states().values()))
        self.run_app(Navigate="Audit")
        self.assertTrue(any("switched off" in m for m in self.st.messages("warning")))

    def test_history_lists_and_deletes(self):
        self.run_app("Run on synthetic sample")
        self.run_app(Navigate="History")
        self.assertTrue(self.st.called("dataframe"))
        self.run_app("Delete this audit", Navigate="History")
        self.assertEqual(self.st.session_state["workspace"].list_audits(), [])
        self.run_app(Navigate="History")
        self.assertTrue(self.st.messages("info"))

    def test_settings_shows_status_and_connection_error(self):
        self.run_app("Test connection", Navigate="Settings")
        self.assertTrue(any("missing" in str(c[1]) for c in self.st.called("write")))
        self.assertTrue(self.st.messages("error"))

    def test_delete_workspace_requires_confirmation_then_logs_out(self):
        ws = self.st.session_state["workspace"]
        self.run_app("Delete workspace", Navigate="Rules & Memory")
        self.assertTrue(ws.path.exists())
        self.run_app("Delete workspace", Navigate="Rules & Memory", **{"Permanently delete this workspace, its rules and its history": True})
        self.assertFalse(ws.path.exists())
        self.assertNotIn("workspace", self.st.session_state)

    def test_logout(self):
        self.run_app("Log out")
        self.assertNotIn("workspace", self.st.session_state)


class NonNemotronWarningTests(AppTestCase):
    ENV = {"AI_PROVIDER": "groq", "AI_API_KEY": "k"}

    def test_settings_warns_when_model_is_not_nemotron(self):
        self.login()
        self.run_app(Navigate="Settings")
        self.assertTrue(any("not a Nemotron model" in m for m in self.st.messages("warning")))


if __name__ == "__main__":
    unittest.main()
