"""Synthetic demo material. Every value in these files is fake."""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from .models import Document, Rule, Severity
from .parsers import parse_document

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"

SAMPLE_RULES: List[Rule] = [
    Rule(
        rule_id="sample.codename", name="Internal project codenames",
        description="Project codenames must not appear in client-facing documents.",
        severity=Severity.HIGH, terms=["Project Bluefin"],
    ),
]


def load_sample(filename: str = "synthetic_sample.txt") -> Document:
    path = SAMPLE_DIR / filename
    return parse_document(path.name, path.read_bytes(), max_bytes=path.stat().st_size + 1)


def sample_files() -> Tuple[str, ...]:
    return ("synthetic_sample.txt", "synthetic_clients.csv")
