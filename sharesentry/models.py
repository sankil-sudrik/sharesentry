"""Domain types shared by every layer. Plain dataclasses, JSON round-trippable."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        try:
            return cls[str(value).upper()]
        except KeyError:
            raise ValueError(f"Unknown severity: {value!r}") from None

    def raised_to(self, floor: "Severity") -> "Severity":
        return self if self >= floor else floor

    def lowered(self) -> "Severity":
        return Severity(max(Severity.LOW, self - 1))


class Category(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    CLOUD_ACCESS_KEY = "cloud_access_key"
    USER_TERM = "user_term"
    INTERNAL_LABEL = "internal_label"
    AI_CONCERN = "ai_concern"

    @property
    def placeholder(self) -> str:
        return self.name


class Context(str, Enum):
    EXTERNAL_CLIENT = "external client"
    PUBLIC_RELEASE = "public release"
    INTERNAL_TEAM = "internal team"


class Status(str, Enum):
    ACTION_REQUIRED = "action_required"
    REVIEW_RECOMMENDED = "review_recommended"
    NO_ISSUES = "no_issues_detected_within_scope"
    INCOMPLETE = "incomplete"

    @property
    def label(self) -> str:
        return {
            Status.ACTION_REQUIRED: "Action required",
            Status.REVIEW_RECOMMENDED: "Review recommended",
            Status.NO_ISSUES: "No issues detected within scope",
            Status.INCOMPLETE: "Incomplete: part of the document could not be inspected",
        }[self]


class Source(str, Enum):
    DETERMINISTIC = "deterministic"
    AI = "ai"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Finding:
    finding_id: str
    category: Category
    severity: Severity
    start: Optional[int]
    end: Optional[int]
    rule_id: str
    confidence: str
    suggested_action: str
    masked_excerpt: str = ""
    source: Source = Source.DETERMINISTIC
    ai_note: str = ""

    @property
    def located(self) -> bool:
        return self.start is not None and self.end is not None

    @property
    def length(self) -> int:
        return (self.end - self.start) if self.located else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category.value,
            "severity": self.severity.name.lower(),
            "start": self.start,
            "end": self.end,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "suggested_action": self.suggested_action,
            "masked_excerpt": self.masked_excerpt,
            "source": self.source.value,
            "ai_note": self.ai_note,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            finding_id=data["finding_id"],
            category=Category(data["category"]),
            severity=Severity.parse(data["severity"]),
            start=data.get("start"),
            end=data.get("end"),
            rule_id=data["rule_id"],
            confidence=data["confidence"],
            suggested_action=data["suggested_action"],
            masked_excerpt=data.get("masked_excerpt", ""),
            source=Source(data.get("source", "deterministic")),
            ai_note=data.get("ai_note", ""),
        )


@dataclass
class Rule:
    """A user-defined privacy rule stored in the workspace memory."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    terms: List[str] = field(default_factory=list)
    contexts: List[Context] = field(default_factory=list)  # empty = every context
    action: str = "Redact before sharing"
    enabled: bool = True

    def applies_to(self, context: Context) -> bool:
        return self.enabled and (not self.contexts or context in self.contexts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.name.lower(),
            "terms": list(self.terms),
            "contexts": [c.value for c in self.contexts],
            "action": self.action,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        return cls(
            rule_id=data["rule_id"],
            name=data["name"],
            description=data.get("description", ""),
            severity=Severity.parse(data["severity"]),
            terms=[str(t) for t in data.get("terms", [])],
            contexts=[Context(c) for c in data.get("contexts", [])],
            action=data.get("action", "Redact before sharing"),
            enabled=bool(data.get("enabled", True)),
        )


@dataclass
class Segment:
    """One structural unit of a document (a CSV cell, DOCX paragraph, PDF page, or whole text)."""

    text: str
    start: int
    ref: Tuple[Any, ...]

    @property
    def end(self) -> int:
        return self.start + len(self.text)


@dataclass
class Document:
    """Parsed document held in memory only; never persisted."""

    name: str
    fmt: str
    segments: List[Segment] = field(default_factory=list)
    scope_notes: List[str] = field(default_factory=list)
    incomplete_reasons: List[str] = field(default_factory=list)
    raw: bytes = b""
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return "\n".join(s.text for s in self.segments)

    @property
    def inspectable(self) -> bool:
        return bool(self.segments)

    def set_segments(self, texts_with_refs: List[Tuple[str, Tuple[Any, ...]]]) -> None:
        """Lay segments out in one joined text, separated by single newlines."""
        self.segments, cursor = [], 0
        for text, ref in texts_with_refs:
            self.segments.append(Segment(text=text, start=cursor, ref=ref))
            cursor += len(text) + 1


@dataclass
class AIOutcome:
    status: str = "skipped"  # skipped | succeeded | failed
    message: str = "AI analysis was not run."
    model: Optional[str] = None
    summary: str = ""
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AIOutcome":
        return cls(**{k: data[k] for k in cls().__dict__ if k in data})


@dataclass
class Verification:
    """Result of re-parsing and re-scanning a redacted output file."""

    output_name: str
    remaining: List[Finding] = field(default_factory=list)
    redacted_count: int = 0

    @property
    def clean(self) -> bool:
        return not self.remaining

    def to_dict(self) -> Dict[str, Any]:
        return {
            "output_name": self.output_name,
            "redacted_count": self.redacted_count,
            "remaining_count": len(self.remaining),
            "remaining": [f.to_dict() for f in self.remaining],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Verification":
        return cls(
            output_name=data["output_name"],
            remaining=[Finding.from_dict(f) for f in data.get("remaining", [])],
            redacted_count=data.get("redacted_count", 0),
        )


@dataclass
class Audit:
    audit_id: str
    document_name: str
    fmt: str
    skill: str
    context: Context
    status: Status
    findings: List[Finding] = field(default_factory=list)
    scope_notes: List[str] = field(default_factory=list)
    incomplete_reasons: List[str] = field(default_factory=list)
    ai: AIOutcome = field(default_factory=AIOutcome)
    verification: Optional[Verification] = None
    created_at: datetime = field(default_factory=utc_now)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "document_name": self.document_name,
            "fmt": self.fmt,
            "skill": self.skill,
            "context": self.context.value,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "scope_notes": list(self.scope_notes),
            "incomplete_reasons": list(self.incomplete_reasons),
            "ai": self.ai.to_dict(),
            "verification": self.verification.to_dict() if self.verification else None,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Audit":
        verification = data.get("verification")
        return cls(
            audit_id=data["audit_id"],
            document_name=data["document_name"],
            fmt=data["fmt"],
            skill=data["skill"],
            context=Context(data["context"]),
            status=Status(data["status"]),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            scope_notes=list(data.get("scope_notes", [])),
            incomplete_reasons=list(data.get("incomplete_reasons", [])),
            ai=AIOutcome.from_dict(data.get("ai", {})),
            verification=Verification.from_dict(verification) if verification else None,
            created_at=datetime.fromisoformat(data["created_at"]),
        )
