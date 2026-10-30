"""Audit reports. They contain masked excerpts and counts only, never raw values or document text."""

from __future__ import annotations

import json
from typing import Any, Dict

from . import __version__
from .models import Audit, Severity

DISCLAIMER = (
    "This report lists what ShareSentry's detectors and optional AI review found. It is not a guarantee: "
    "absence of findings is never proof that a document is safe to share."
)


def report_dict(audit: Audit) -> Dict[str, Any]:
    data = audit.to_dict()
    data.update(
        tool={"name": "ShareSentry", "version": __version__},
        status_label=audit.status.label,
        counts={s.name.lower(): audit.count(s) for s in sorted(Severity, reverse=True)},
        disclaimer=DISCLAIMER,
    )
    return data


def report_json(audit: Audit) -> str:
    return json.dumps(report_dict(audit), indent=2, ensure_ascii=False)


def report_markdown(audit: Audit) -> str:
    counts = ", ".join(f"{s.label}: {audit.count(s)}" for s in sorted(Severity, reverse=True))
    lines = [
        f"# ShareSentry audit: {audit.document_name}",
        "",
        f"- **Status:** {audit.status.label}",
        f"- **Skill:** {audit.skill} | **Context:** {audit.context.value}",
        f"- **Run:** {audit.created_at:%Y-%m-%d %H:%M} UTC | **Audit ID:** {audit.audit_id}",
        f"- **Findings:** {len(audit.findings)} ({counts})",
        f"- **AI review:** {audit.ai.status}. {audit.ai.message}",
        "",
    ]
    if audit.incomplete_reasons:
        lines += ["## Not inspected", *[f"- {r}" for r in audit.incomplete_reasons], ""]
    if audit.scope_notes:
        lines += ["## Scope limits", *[f"- {n}" for n in audit.scope_notes], ""]
    if audit.findings:
        lines += ["## Findings", "", "| ID | Severity | Category | Source | Confidence | Masked excerpt |", "|---|---|---|---|---|---|"]
        for f in audit.findings:
            excerpt = f.masked_excerpt.replace("|", "\\|")
            lines.append(f"| {f.finding_id} | {f.severity.label} | {f.category.value} | {f.source.value} | {f.confidence} | {excerpt} |")
        lines.append("")
    if audit.verification:
        v = audit.verification
        outcome = "no findings remain" if v.clean else f"{len(v.remaining)} finding(s) remain"
        lines += ["## Redaction check", f"Output `{v.output_name}`: {v.redacted_count} redaction(s) applied; rescan of the produced file: {outcome}.", ""]
    lines += ["---", DISCLAIMER]
    return "\n".join(lines)
