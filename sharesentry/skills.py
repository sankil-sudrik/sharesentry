"""Reusable audit skills. A skill changes which detectors run and how severe findings are."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Mapping

from .models import Category, Context, Finding, Severity

ALL_CATEGORIES = frozenset(c for c in Category if c is not Category.AI_CONCERN)
SECRET_CATEGORIES = frozenset({Category.API_KEY, Category.PRIVATE_KEY, Category.CLOUD_ACCESS_KEY, Category.CREDIT_CARD})
CONTEXT_RELAXED = frozenset({Category.INTERNAL_LABEL, Category.USER_TERM})


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    default_context: Context
    categories: FrozenSet[Category]
    severity_floor: Mapping[Category, Severity] = field(default_factory=dict)
    ai_focus: str = ""
    csv_minimizer: bool = False


SKILLS: List[Skill] = [
    Skill(
        name="Client-Ready Review",
        description="Check a deliverable against your confidentiality rules before it goes to an external client.",
        default_context=Context.EXTERNAL_CLIENT,
        categories=ALL_CATEGORIES,
        severity_floor={
            Category.EMAIL: Severity.MEDIUM,
            Category.PHONE: Severity.MEDIUM,
            Category.INTERNAL_LABEL: Severity.HIGH,
            Category.USER_TERM: Severity.HIGH,
        },
        ai_focus="internal pricing or margins, other clients' details, internal project names, and negotiation notes",
    ),
    Skill(
        name="Secrets & Credentials Scan",
        description="Look only for credentials: API tokens, private keys, cloud keys and payment card numbers.",
        default_context=Context.PUBLIC_RELEASE,
        categories=SECRET_CATEGORIES,
        severity_floor={Category.API_KEY: Severity.CRITICAL, Category.CREDIT_CARD: Severity.CRITICAL},
        ai_focus="connection strings, passwords in prose, and credentials that do not follow a standard format",
    ),
    Skill(
        name="Public Release Review",
        description="Strict review for anything going on a public website, repository or social post.",
        default_context=Context.PUBLIC_RELEASE,
        categories=ALL_CATEGORIES,
        severity_floor={
            Category.EMAIL: Severity.HIGH,
            Category.PHONE: Severity.HIGH,
            Category.INTERNAL_LABEL: Severity.HIGH,
            Category.USER_TERM: Severity.HIGH,
            Category.CREDIT_CARD: Severity.CRITICAL,
        },
        ai_focus="personal data, unreleased plans, internal URLs and anything not meant for the public",
    ),
    Skill(
        name="CSV Data Minimizer",
        description="Find sensitive columns in tabular data and produce a reduced copy, optionally dropping whole columns.",
        default_context=Context.EXTERNAL_CLIENT,
        categories=ALL_CATEGORIES,
        severity_floor={Category.EMAIL: Severity.MEDIUM, Category.PHONE: Severity.MEDIUM},
        ai_focus="columns or values that identify individuals or are unnecessary for the recipient's purpose",
        csv_minimizer=True,
    ),
]

SKILLS_BY_NAME: Dict[str, Skill] = {s.name: s for s in SKILLS}


def apply_skill(findings: List[Finding], skill: Skill, context: Context) -> None:
    """Apply the skill's severity floors, then relax context-sensitive findings for internal sharing."""
    for finding in findings:
        floor = skill.severity_floor.get(finding.category)
        if floor is not None:
            finding.severity = finding.severity.raised_to(floor)
        if context is Context.INTERNAL_TEAM and finding.category in CONTEXT_RELAXED:
            finding.severity = finding.severity.lowered()
