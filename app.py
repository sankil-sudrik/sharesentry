"""ShareSentry: Streamlit interface. All logic lives in the `sharesentry` package."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Callable, Dict, List

import streamlit as st


def load_custom_css() -> None:
    """Inject neumorphism custom CSS."""
    css_path = Path(__file__).parent / ".streamlit" / "neumorphism.css"
    if css_path.exists():
        st.html(f"<style>{css_path.read_text()}</style>")

from sharesentry.ai import AIError, list_models
from sharesentry.audit import csv_column_summary, run_audit, verify_redaction
from sharesentry.config import Settings, load_settings
from sharesentry.models import Context, Rule, Severity, Status
from sharesentry.parsers import SUPPORTED, parse_document
from sharesentry.redaction import redact_document
from sharesentry.report import DISCLAIMER, report_json, report_markdown
from sharesentry.sample import SAMPLE_RULES, load_sample
from sharesentry.skills import SKILLS, SKILLS_BY_NAME
from sharesentry.store import AuthError, Workspace

BANNER = {
    Status.ACTION_REQUIRED: st.error,
    Status.REVIEW_RECOMMENDED: st.warning,
    Status.NO_ISSUES: st.success,
    Status.INCOMPLETE: st.warning,
}
CONSENT_TEXT = (
    "Send a masked copy of this document to the configured AI endpoint for contextual review. "
    "Detected values are replaced by placeholders first; rule terms are never sent."
)


# ----------------------------------------------------------------------------- login
def render_login(settings: Settings) -> None:
    st.title("ShareSentry")
    st.caption("Check a document before you share it. Findings are evidence, not a guarantee.")
    mode = st.radio("Workspace", ["Open existing", "Create new"], horizontal=True)
    name = st.text_input("Workspace name")
    passphrase = st.text_input("Passphrase", type="password", help="At least 8 characters. Stored only as a salted hash.")
    if not st.button(mode):
        return
    try:
        opener = Workspace.open if mode == "Open existing" else Workspace.create
        st.session_state["workspace"] = opener(settings.data_dir, name, passphrase)
    except (AuthError, ValueError) as exc:
        st.error(str(exc))
        return
    st.rerun()


# ----------------------------------------------------------------------------- audit page
def page_audit(ws: Workspace, settings: Settings) -> None:
    st.header("New audit")
    states = ws.skill_states()
    enabled = [s.name for s in SKILLS if states[s.name]]
    if not enabled:
        st.warning("Every skill is switched off. Enable at least one on the Skills page.")
        return
    skill = SKILLS_BY_NAME[st.selectbox("Skill", enabled)]
    st.caption(skill.description)
    contexts = list(Context)
    context = st.selectbox("Sharing context", contexts, index=contexts.index(skill.default_context),
                           format_func=lambda c: c.value, key=f"context-{skill.name}")
    upload = st.file_uploader("Document", type=list(SUPPORTED))
    use_ai = st.checkbox(CONSENT_TEXT, disabled=not settings.ai.configured)
    if not settings.ai.configured:
        st.caption("AI review is off: add AI_API_KEY to .env (see Settings). Deterministic checks still run.")

    left, right = st.columns(2)
    run_clicked, sample_clicked = left.button("Run audit"), right.button("Run on synthetic sample")
    if run_clicked and upload is None:
        st.error("Choose a document first.")
    elif run_clicked or sample_clicked:
        if sample_clicked:
            doc, rules = load_sample("synthetic_clients.csv" if skill.csv_minimizer else "synthetic_sample.txt"), SAMPLE_RULES
        else:
            doc, rules = parse_document(upload.name, upload.getvalue(), settings.max_upload_bytes), []
        with st.spinner("Auditing..."):
            audit = run_audit(doc, skill, context, ws.list_rules() + list(rules), settings.ai, use_ai)
        ws.save_audit(audit)
        st.session_state["current"] = {"doc": doc, "audit": audit, "skill": skill.name, "result": None, "extra_rules": list(rules)}
    if "current" in st.session_state:
        render_results(ws, st.session_state["current"])


def render_results(ws: Workspace, current: Dict) -> None:
    audit = current["audit"]
    st.divider()
    st.subheader(f"Results: {audit.document_name}")
    BANNER[audit.status](audit.status.label)
    st.caption(DISCLAIMER)
    for reason in audit.incomplete_reasons:
        st.warning(f"Not inspected: {reason}")
    if audit.scope_notes:
        with st.expander("Scope limits"):
            for note in audit.scope_notes:
                st.markdown(f"- {note}")
    st.caption(f"AI review ({audit.ai.status}): {audit.ai.message}")
    if audit.ai.summary:
        st.info(audit.ai.summary)

    for column, severity in zip(st.columns(4), sorted(Severity, reverse=True)):
        column.metric(severity.label, audit.count(severity))
    if audit.findings:
        st.dataframe([
            {"ID": f.finding_id, "Severity": f.severity.label, "Category": f.category.value, "Source": f.source.value,
             "Confidence": f.confidence, "Masked excerpt": f.masked_excerpt, "AI note": f.ai_note}
            for f in audit.findings
        ])
        render_redaction(ws, current)
    st.download_button("Download report (JSON)", report_json(audit), f"{audit.audit_id}.json", "application/json")
    st.download_button("Download report (Markdown)", report_markdown(audit), f"{audit.audit_id}.md", "text/markdown")


def render_redaction(ws: Workspace, current: Dict) -> None:
    audit, doc = current["audit"], current["doc"]
    skill = SKILLS_BY_NAME[current["skill"]]
    located = [f for f in audit.findings if f.located]
    if len(located) < len(audit.findings):
        st.caption("Findings without an exact location (AI concerns) need manual review; they cannot be auto-redacted.")
    if not located:
        return
    st.subheader("Redact")
    by_id = {f.finding_id: f for f in located}
    chosen = st.multiselect("Findings to redact", list(by_id), default=list(by_id), key=f"sel-{audit.audit_id}",
                            format_func=lambda i: f"{i}: {by_id[i].category.value} ({by_id[i].severity.label})")
    drop: List[int] = []
    if skill.csv_minimizer and doc.fmt == "csv":
        columns = csv_column_summary(doc, audit.findings)
        labels = {c["column"]: f"{c['name']} ({c['findings']} finding(s))" for c in columns}
        drop = st.multiselect("Columns to remove entirely", list(labels), format_func=labels.get, key=f"drop-{audit.audit_id}")
    if st.button("Generate redacted copy"):
        result = redact_document(doc, audit.findings, chosen, drop)
        audit.verification = verify_redaction(result, audit, skill, ws.list_rules() + current["extra_rules"])
        ws.save_audit(audit)
        current["result"] = result
    result = current["result"]
    if result is None:
        return
    check = audit.verification
    (st.success if check.clean else st.warning)(
        f"Re-scan of the produced file: {'no findings remain' if check.clean else f'{len(check.remaining)} finding(s) remain (not selected, or not removable)'}."
    )
    if doc.fmt == "pdf":
        st.caption("The PDF copy is rebuilt as plain text; original layout and images are not preserved.")
    st.download_button("Download redacted copy", result.data, result.name, result.mime)


# ----------------------------------------------------------------------------- rules & memory
def page_rules(ws: Workspace, settings: Settings) -> None:
    st.header("Privacy rules and memory")
    st.caption("Rules persist in this workspace and apply to every audit. Terms are matched as whole words, ignoring case.")
    for rule in ws.list_rules():
        with st.expander(f"{rule.name} ({rule.severity.label})"):
            st.write(rule.description or "No description.")
            st.write(f"Terms: {', '.join(rule.terms) or 'none'} | Contexts: {', '.join(c.value for c in rule.contexts) or 'all'}")
            enabled = st.checkbox("Enabled", rule.enabled, key=f"on-{rule.rule_id}")
            if enabled != rule.enabled:
                rule.enabled = enabled
                ws.save_rule(rule)
                st.rerun()
            if st.button("Delete rule", key=f"del-{rule.rule_id}"):
                ws.delete_rule(rule.rule_id)
                st.rerun()
    with st.form("add-rule", clear_on_submit=True):
        st.subheader("Add a rule")
        name = st.text_input("Name")
        description = st.text_area("What it protects")
        severity = st.selectbox("Severity", list(Severity), index=2, format_func=lambda s: s.label)
        terms = st.text_area("Terms (one per line)")
        contexts = st.multiselect("Only in these contexts (empty = all)", list(Context), format_func=lambda c: c.value)
        action = st.text_input("Recommended action", "Redact before sharing")
        if st.form_submit_button("Add rule"):
            term_list = [t.strip() for t in terms.splitlines() if t.strip()]
            if not name.strip() or not term_list:
                st.error("A rule needs a name and at least one term.")
            else:
                ws.save_rule(Rule(f"rule_{uuid.uuid4().hex[:8]}", name.strip(), description.strip(), severity, term_list, contexts, action.strip()))
                st.rerun()
    render_backup(ws)


def render_backup(ws: Workspace) -> None:
    st.subheader("Backup and restore")
    include_terms = st.checkbox("Include rule terms in the backup", True, help="Terms may themselves be confidential.")
    st.download_button("Export workspace backup", json.dumps(ws.export_backup(include_terms), indent=2), "sharesentry-backup.json", "application/json")
    backup = st.file_uploader("Restore from backup", type=["json"], key="restore")
    if backup is not None and st.button("Import backup"):
        try:
            counts = ws.import_backup(json.loads(backup.getvalue()))
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.success(f"Imported {counts['rules']} rule(s), {counts['audits']} audit(s), {counts['skills']} skill setting(s).")
    st.subheader("Delete workspace")
    confirmed = st.checkbox("Permanently delete this workspace, its rules and its history")
    if st.button("Delete workspace", disabled=not confirmed):
        ws.delete()
        st.session_state.clear()
        st.rerun()


# ----------------------------------------------------------------------------- skills, history, settings
def page_skills(ws: Workspace, settings: Settings) -> None:
    st.header("Skills")
    st.caption("Skills are reusable audit workflows. They change which detectors run and how severe findings are.")
    states = ws.skill_states()
    for skill in SKILLS:
        with st.expander(skill.name, expanded=True):
            st.write(skill.description)
            st.caption(f"Detects: {', '.join(sorted(c.value for c in skill.categories))}")
            on = st.checkbox("Enabled", states[skill.name], key=f"skill-{skill.name}")
            if on != states[skill.name]:
                ws.set_skill_enabled(skill.name, on)
                st.rerun()


def page_history(ws: Workspace, settings: Settings) -> None:
    st.header("History")
    audits = ws.list_audits()
    if not audits:
        st.info("No audits yet.")
        return
    st.dataframe([
        {"When": a.created_at.strftime("%Y-%m-%d %H:%M"), "Document": a.document_name, "Skill": a.skill,
         "Status": a.status.label, "Findings": len(a.findings), "ID": a.audit_id}
        for a in audits
    ])
    labels = {a.audit_id: f"{a.document_name} ({a.audit_id})" for a in audits}
    chosen = next(a for a in audits if a.audit_id == st.selectbox("Open an audit", list(labels), format_func=labels.get))
    st.markdown(report_markdown(chosen))
    st.download_button("Download report (JSON)", report_json(chosen), f"{chosen.audit_id}.json", "application/json", key="hist-json")
    if st.button("Delete this audit"):
        ws.delete_audit(chosen.audit_id)
        st.rerun()


def page_settings(ws: Workspace, settings: Settings) -> None:
    st.header("Settings")
    ai = settings.ai
    st.write(f"**Provider:** {ai.provider_label}  \n**Endpoint:** `{ai.base_url or 'not set'}`  \n**Model:** `{ai.model or 'not set'}`")
    st.write(f"**API key:** {'configured' if ai.api_key else 'missing (set AI_API_KEY in .env)'}")
    if not ai.is_nemotron:
        st.warning("The configured model is not a Nemotron model. Reports will name the model actually used.")
    st.write(f"**Upload limit:** {settings.max_upload_mb} MB | **AI input limit:** {ai.max_input_chars} characters | **Timeout:** {ai.timeout_seconds:g}s")
    if st.button("Test connection"):
        try:
            models = list_models(ai)
        except AIError as exc:
            st.error(str(exc))
            return
        nemotron = [m for m in models if "nemotron" in m.lower()]
        if ai.model in models:
            st.success(f"Connected. The configured model '{ai.model}' is available.")
        else:
            st.warning(f"Connected, but '{ai.model}' was not listed. Nemotron models offered: {', '.join(nemotron) or 'none'}.")


PAGES: Dict[str, Callable[[Workspace, Settings], None]] = {
    "Audit": page_audit,
    "Rules & Memory": page_rules,
    "Skills": page_skills,
    "History": page_history,
    "Settings": page_settings,
}


def main() -> None:
    st.set_page_config(page_title="ShareSentry", page_icon="🛡️", layout="wide")
    load_custom_css()
    try:
        settings = load_settings()
    except ValueError as exc:
        st.error(f"Configuration error: {exc}")
        return
    ws = st.session_state.get("workspace")
    if ws is None:
        render_login(settings)
        return
    page = st.sidebar.radio("Navigate", list(PAGES))
    st.sidebar.caption(f"Workspace: {ws.path.stem}")
    if st.sidebar.button("Log out"):
        st.session_state.clear()
        st.rerun()
    PAGES[page](ws, settings)


main()
