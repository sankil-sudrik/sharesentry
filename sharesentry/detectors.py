"""Deterministic detectors. Each returns located Findings with exact offsets into the input text.

No detector ever stores the matched value: callers receive offsets, and `mask_text`
produces excerpts in which every finding is replaced by a `[CATEGORY]` placeholder.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

from .models import Category, Finding, Rule, Severity

REDACTION_PLACEHOLDER = re.compile(r"\[REDACTED:[A-Z_]+\]")
EXCERPT_RADIUS = 40


def _finding(
    category: Category,
    severity: Severity,
    start: int,
    end: int,
    rule_id: str,
    confidence: str,
    action: str,
) -> Finding:
    return Finding("", category, severity, start, end, rule_id, confidence, action)


def _spans(pattern: Pattern[str], text: str, group: int = 0) -> Iterable[Tuple[int, int]]:
    for match in pattern.finditer(text):
        yield match.span(group)


# --------------------------------------------------------------------------- email
EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"
)


def detect_emails(text: str) -> List[Finding]:
    return [
        _finding(Category.EMAIL, Severity.LOW, s, e, "builtin.email", "pattern match", "Redact or replace with a role address")
        for s, e in _spans(EMAIL_RE, text)
    ]


# --------------------------------------------------------------------------- phone
PHONE_PATTERNS = (
    re.compile(r"(?<![\w+])\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){2,4}(?!\w)"),
    re.compile(r"(?<![\w.])(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]\d{4}(?!\w)"),
    re.compile(r"(?<![\w+])[6-9]\d{4}[ -]?\d{5}(?!\w)"),
)
DOTTED_QUAD_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PHONE_CONFIDENCE = "uncertain: format-based match, not verified as a phone number"


def _plausible_phone(candidate: str) -> bool:
    digits = re.sub(r"\D", "", candidate)
    return 9 <= len(digits) <= 15 and not DOTTED_QUAD_RE.match(candidate)


def detect_phones(text: str) -> List[Finding]:
    return merge_overlapping([
        _finding(Category.PHONE, Severity.MEDIUM, s, e, "builtin.phone", PHONE_CONFIDENCE, "Review; redact if it is a real number")
        for pattern in PHONE_PATTERNS
        for s, e in _spans(pattern, text)
        if _plausible_phone(text[s:e])
    ])


# --------------------------------------------------------------------------- credit card
CARD_RE = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


def detect_credit_cards(text: str) -> List[Finding]:
    return [
        _finding(Category.CREDIT_CARD, Severity.HIGH, s, e, "builtin.credit_card", "validated: Luhn checksum passes", "Redact")
        for s, e in _spans(CARD_RE, text)
        if luhn_valid(text[s:e])
    ]


# --------------------------------------------------------------------------- API keys / tokens
_NOT_PLACEHOLDER = r"(?!\[REDACTED)"
TOKEN_PATTERNS = (
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b[pr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\bnvapi-[A-Za-z0-9_-]{20,}"),
)
ASSIGNMENT_RE = re.compile(
    r"""(?ix)\b(?:api[_-]?key|secret|token|password|passwd|pwd)\b["']?\s*[:=]\s*["']?
        (?P<value>""" + _NOT_PLACEHOLDER + r"""[^\s"',;]{8,})"""
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+(?P<value>" + _NOT_PLACEHOLDER + r"[A-Za-z0-9._~+/=-]{20,})")


def detect_api_keys(text: str) -> List[Finding]:
    spans = [(s, e, "known token format") for p in TOKEN_PATTERNS for s, e in _spans(p, text)]
    spans += [(*m.span("value"), "credential assignment") for p in (ASSIGNMENT_RE, BEARER_RE) for m in p.finditer(text)]
    return merge_overlapping([
        _finding(Category.API_KEY, Severity.HIGH, s, e, "builtin.api_key", f"pattern match: {kind}", "Revoke if real, then redact")
        for s, e, kind in spans
    ])


# --------------------------------------------------------------------------- private keys
_PEM_KIND = r"(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?"
PEM_BLOCK_RE = re.compile(rf"-----BEGIN {_PEM_KIND}-----[\s\S]*?-----END {_PEM_KIND}-----")
PEM_HEADER_RE = re.compile(rf"-----BEGIN {_PEM_KIND}-----")


def detect_private_keys(text: str) -> List[Finding]:
    blocks = list(_spans(PEM_BLOCK_RE, text))
    headers = [
        span for span in _spans(PEM_HEADER_RE, text)
        if not any(bs <= span[0] < be for bs, be in blocks)
    ]
    rule = "builtin.private_key"
    action = "Revoke and rotate the key, then remove it"
    found = [_finding(Category.PRIVATE_KEY, Severity.CRITICAL, s, e, rule, "pattern match: complete PEM block", action) for s, e in blocks]
    found += [
        _finding(Category.PRIVATE_KEY, Severity.CRITICAL, s, e, rule, "pattern match: PEM header only (block end not found)", action)
        for s, e in headers
    ]
    return found


# --------------------------------------------------------------------------- cloud access keys
AWS_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_RE = re.compile(
    r"""(?ix)aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?(?P<value>""" + _NOT_PLACEHOLDER + r"""[A-Za-z0-9/+=]{40})"""
)


def detect_cloud_keys(text: str) -> List[Finding]:
    spans = list(_spans(AWS_KEY_ID_RE, text)) + [m.span("value") for m in AWS_SECRET_RE.finditer(text)]
    return merge_overlapping([
        _finding(Category.CLOUD_ACCESS_KEY, Severity.CRITICAL, s, e, "builtin.cloud_key", "pattern match: AWS key format", "Deactivate the key in the cloud console, then redact")
        for s, e in spans
    ])


# --------------------------------------------------------------------------- internal labels
LABEL_RE = re.compile(
    r"(?i)\b(?:internal use only|internal only|do not distribute|do not share|not for distribution|"
    r"confidential|proprietary|trade secret|attorney[- ]client privileged)\b"
)


def detect_internal_labels(text: str) -> List[Finding]:
    return [
        _finding(Category.INTERNAL_LABEL, Severity.MEDIUM, s, e, "builtin.internal_label", "pattern match: confidentiality marking", "Confirm the document may leave the organization")
        for s, e in _spans(LABEL_RE, text)
    ]


# --------------------------------------------------------------------------- user terms (workspace rules)
def detect_user_terms(text: str, rules: Sequence[Rule]) -> List[Finding]:
    found: List[Finding] = []
    for rule in rules:
        for term in {t.strip() for t in rule.terms if len(t.strip()) >= 2}:
            pattern = re.compile(rf"(?<!\w){re.escape(term)}(?!\w)", re.IGNORECASE)
            found += [
                _finding(Category.USER_TERM, rule.severity, s, e, rule.rule_id, "exact term match (whole word, case-insensitive)", rule.action)
                for s, e in _spans(pattern, text)
            ]
    return found


# --------------------------------------------------------------------------- registry and orchestration
BUILTIN_DETECTORS: Dict[Category, Callable[[str], List[Finding]]] = {
    Category.EMAIL: detect_emails,
    Category.PHONE: detect_phones,
    Category.CREDIT_CARD: detect_credit_cards,
    Category.API_KEY: detect_api_keys,
    Category.PRIVATE_KEY: detect_private_keys,
    Category.CLOUD_ACCESS_KEY: detect_cloud_keys,
    Category.INTERNAL_LABEL: detect_internal_labels,
}


def _neutralize_placeholders(text: str) -> str:
    """Blank out our own redaction placeholders (same length) so re-scans never flag them."""
    return REDACTION_PLACEHOLDER.sub(lambda m: " " * len(m.group()), text)


def detect(
    text: str,
    categories: Optional[Iterable[Category]] = None,
    rules: Sequence[Rule] = (),
) -> List[Finding]:
    """Run the selected detectors (all built-ins by default) plus user-term rules."""
    scan = _neutralize_placeholders(text)
    wanted = set(categories) if categories is not None else set(Category)
    found: List[Finding] = []
    for category, detector in BUILTIN_DETECTORS.items():
        if category in wanted:
            found += detector(scan)
    if Category.USER_TERM in wanted:
        found += detect_user_terms(scan, rules)
    return found


def merge_overlapping(findings: Sequence[Finding]) -> List[Finding]:
    """Union overlapping spans. The most severe (then longest) member names the merged finding."""
    located = sorted((f for f in findings if f.located), key=lambda f: (f.start, -f.end))
    merged: List[Finding] = []
    cluster: List[Finding] = []
    cluster_end = -1
    for finding in located + [None]:
        if finding is not None and cluster and finding.start < cluster_end:
            cluster.append(finding)
            cluster_end = max(cluster_end, finding.end)
            continue
        if cluster:
            winner = max(cluster, key=lambda f: (f.severity, f.length))
            merged.append(Finding(
                "", winner.category, winner.severity, min(f.start for f in cluster), cluster_end,
                winner.rule_id, winner.confidence, winner.suggested_action, source=winner.source,
            ))
        cluster, cluster_end = ([finding], finding.end) if finding is not None else ([], -1)
    return merged + [f for f in findings if not f.located]


def mask_text(text: str, findings: Sequence[Finding]) -> Tuple[str, Dict[int, Tuple[int, int]]]:
    """Replace every located finding with `[CATEGORY]`.

    Returns the masked text and, per input-finding index, its span in the masked text.
    Findings must not overlap (run `merge_overlapping` first).
    """
    order = sorted((i for i, f in enumerate(findings) if f.located), key=lambda i: findings[i].start)
    pieces: List[str] = []
    spans: Dict[int, Tuple[int, int]] = {}
    cursor, length = 0, 0
    for index in order:
        finding = findings[index]
        label = f"[{finding.category.placeholder}]"
        head = text[cursor:finding.start]
        pieces += [head, label]
        spans[index] = (length + len(head), length + len(head) + len(label))
        length += len(head) + len(label)
        cursor = finding.end
    pieces.append(text[cursor:])
    return "".join(pieces), spans


def attach_excerpts(text: str, findings: List[Finding]) -> str:
    """Fill `masked_excerpt` on each located finding and return the fully masked text."""
    masked, spans = mask_text(text, findings)
    for index, (start, end) in spans.items():
        window = masked[max(0, start - EXCERPT_RADIUS):end + EXCERPT_RADIUS]
        findings[index].masked_excerpt = re.sub(r"\s+", " ", window).strip()
    return masked
