"""Audit pipeline: parse result -> deterministic findings -> optional AI review -> status -> redaction check."""

from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Sequence, Tuple

from . import ai as ai_module
from .config import AIConfig
from .detectors import attach_excerpts, detect, merge_overlapping
from .models import Audit, Category, Context, Document, Finding, Rule, Severity, Source, Status, Verification
from .parsers import parse_document
from .redaction import RedactionResult
from .skills import Skill, apply_skill

AI_SEVERITY = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}


def scan_text(
    text: str, skill: Skill, context: Context, rules: Sequence[Rule]
) -> Tuple[List[Finding], str]:
    """Deterministic scan shared by the audit and by redaction verification.

    Returns numbered findings (skill and context applied, excerpts masked) and the masked text.
    """
    applicable = [r for r in rules if r.applies_to(context)]
    findings = merge_overlapping(detect(text, skill.categories, applicable))
    for number, finding in enumerate(findings, start=1):
        finding.finding_id = f"F{number:03d}"
    apply_skill(findings, skill, context)
    return findings, attach_excerpts(text, findings)


def determine_status(findings: Sequence[Finding], incomplete_reasons: Sequence[str]) -> Status:
    """Findings drive the status; uninspected content can only block a clean result, never hide a finding."""
    if any(f.severity >= Severity.HIGH for f in findings):
        return Status.ACTION_REQUIRED
    if findings:
        return Status.REVIEW_RECOMMENDED
    return Status.INCOMPLETE if incomplete_reasons else Status.NO_ISSUES


def _locate_concern(text: str, quote: str, taken: Sequence[Finding]) -> Optional[Tuple[int, int]]:
    first = text.find(quote)
    if first < 0 or text.find(quote, first + 1) >= 0:
        return None  # absent or ambiguous
    end = first + len(quote)
    return None if any(f.located and f.start < end and first < f.end for f in taken) else (first, end)


def _add_ai_findings(findings: List[Finding], analysis: ai_module.AIAnalysis, text: str) -> None:
    for finding in findings:
        verdict = analysis.assessments.get(finding.finding_id)
        if verdict:
            finding.ai_note = f"AI: {verdict['relevance']}. {verdict['rationale']}".strip()
    for concern in analysis.concerns:
        span = _locate_concern(text, concern.quote, findings)
        start, end = span if span else (None, None)
        findings.append(Finding(
            finding_id=f"F{len(findings) + 1:03d}", category=Category.AI_CONCERN,
            severity=AI_SEVERITY[concern.severity], start=start, end=end, rule_id="ai.contextual",
            confidence="ai-suggested; quote verified in document" if span else "ai-suggested; location not unique, review manually",
            suggested_action="Review manually" if not span else "Review and redact if confidential",
            masked_excerpt=concern.quote, source=Source.AI, ai_note=f"AI: {concern.reason}",
        ))


def run_audit(
    doc: Document,
    skill: Skill,
    context: Context,
    rules: Sequence[Rule] = (),
    ai_config: Optional[AIConfig] = None,
    use_ai: bool = False,
    transport: ai_module.Transport = ai_module.http_json,
) -> Audit:
    audit = Audit(
        audit_id=f"audit_{uuid.uuid4().hex[:12]}", document_name=doc.name, fmt=doc.fmt, skill=skill.name,
        context=context, status=Status.INCOMPLETE, scope_notes=list(doc.scope_notes),
        incomplete_reasons=list(doc.incomplete_reasons),
    )
    if skill.csv_minimizer and doc.fmt != "csv":
        audit.scope_notes.append("CSV Data Minimizer is designed for CSV files; standard checks were applied.")
    if not doc.inspectable:
        return audit

    text = doc.text
    audit.findings, masked = scan_text(text, skill, context, rules)
    if use_ai:
        analysis = ai_module.analyze(
            ai_config or AIConfig(), masked, audit.findings, context, skill.ai_focus, rules, consent=True, transport=transport,
        )
        audit.ai = analysis.outcome
        if analysis.outcome.status == "succeeded":
            _add_ai_findings(audit.findings, analysis, text)
    audit.status = determine_status(audit.findings, audit.incomplete_reasons)
    return audit


def verify_redaction(
    result: RedactionResult, audit: Audit, skill: Skill, rules: Sequence[Rule]
) -> Verification:
    """Re-parse the produced file and rescan it, so the report reflects the real output."""
    output = parse_document(result.name, result.data, max_bytes=len(result.data) + 1)
    remaining = scan_text(output.text, skill, audit.context, rules)[0] if output.inspectable else []
    return Verification(output_name=result.name, remaining=remaining, redacted_count=result.applied)


def csv_column_summary(doc: Document, findings: Sequence[Finding]) -> List[Dict[str, object]]:
    """Per-column finding counts for CSV files (header row names the columns)."""
    if doc.fmt != "csv":
        return []
    header = doc.meta["rows"][0] if doc.meta.get("rows") else []
    counts: Dict[int, int] = {}
    for finding in findings:
        if not finding.located:
            continue
        for segment in doc.segments:
            if segment.start <= finding.start < segment.end:
                column = segment.ref[2]
                counts[column] = counts.get(column, 0) + 1
                break
    return [
        {"column": column, "name": header[column] if column < len(header) and header[column].strip() else f"column {column + 1}",
         "findings": count}
        for column, count in sorted(counts.items())
    ]
