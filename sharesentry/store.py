"""Persistent, passphrase-gated workspace: rules, skill toggles and audit history in SQLite.

The passphrase is stored only as a salted scrypt hash. Documents and their text are never
written; audits hold masked excerpts. The database file itself is NOT encrypted at rest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .models import Audit, Rule
from .skills import SKILLS

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
MIN_PASSPHRASE = 8
BACKUP_VERSION = 1
SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta   (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS rules  (rule_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audits (audit_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS skills (name TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
"""


class AuthError(Exception):
    """Wrong passphrase or unknown workspace."""


def _hash(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, **SCRYPT)


def workspace_path(data_dir: Path, name: str) -> Path:
    slug = name.strip().lower()
    if not NAME_RE.match(slug):
        raise ValueError("Workspace names use 1-40 letters, digits, '-' or '_'.")
    return Path(data_dir) / f"{slug}.sqlite3"


class Workspace:
    def __init__(self, path: Path):
        self.path = Path(path)

    # ----------------------------------------------------------------- lifecycle
    @classmethod
    def exists(cls, data_dir: Path, name: str) -> bool:
        return workspace_path(data_dir, name).exists()

    @classmethod
    def create(cls, data_dir: Path, name: str, passphrase: str) -> "Workspace":
        if len(passphrase) < MIN_PASSPHRASE:
            raise ValueError(f"The passphrase must be at least {MIN_PASSPHRASE} characters.")
        path = workspace_path(data_dir, name)
        if path.exists():
            raise ValueError("A workspace with this name already exists.")
        path.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        workspace = cls(path)
        with workspace._db() as db:
            db.executemany("INSERT INTO meta VALUES (?, ?)", [("salt", salt), ("hash", _hash(passphrase, salt))])
        return workspace

    @classmethod
    def open(cls, data_dir: Path, name: str, passphrase: str) -> "Workspace":
        path = workspace_path(data_dir, name)
        if not path.exists():
            raise AuthError("Unknown workspace or wrong passphrase.")
        workspace = cls(path)
        with workspace._db() as db:
            stored = dict(db.execute("SELECT key, value FROM meta").fetchall())
        if "salt" not in stored or not hmac.compare_digest(_hash(passphrase, stored["salt"]), stored.get("hash", b"")):
            raise AuthError("Unknown workspace or wrong passphrase.")
        return workspace

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript(SCHEMA)
            yield connection
            connection.commit()
        finally:
            connection.close()

    # ----------------------------------------------------------------- rules
    def save_rule(self, rule: Rule) -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO rules VALUES (?, ?)", (rule.rule_id, json.dumps(rule.to_dict())))

    def list_rules(self) -> List[Rule]:
        with self._db() as db:
            return [Rule.from_dict(json.loads(body)) for (body,) in db.execute("SELECT body FROM rules ORDER BY rowid")]

    def delete_rule(self, rule_id: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM rules WHERE rule_id = ?", (rule_id,))

    # ----------------------------------------------------------------- skills
    def skill_states(self) -> Dict[str, bool]:
        """Every built-in skill is enabled unless the user switched it off."""
        with self._db() as db:
            saved = dict(db.execute("SELECT name, enabled FROM skills").fetchall())
        return {skill.name: bool(saved.get(skill.name, 1)) for skill in SKILLS}

    def set_skill_enabled(self, name: str, enabled: bool) -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO skills VALUES (?, ?)", (name, int(enabled)))

    # ----------------------------------------------------------------- audits
    def save_audit(self, audit: Audit) -> None:
        with self._db() as db:
            db.execute(
                "INSERT OR REPLACE INTO audits VALUES (?, ?, ?)",
                (audit.audit_id, audit.created_at.isoformat(), json.dumps(audit.to_dict())),
            )

    def get_audit(self, audit_id: str) -> Optional[Audit]:
        with self._db() as db:
            row = db.execute("SELECT body FROM audits WHERE audit_id = ?", (audit_id,)).fetchone()
        return Audit.from_dict(json.loads(row[0])) if row else None

    def list_audits(self, limit: int = 100) -> List[Audit]:
        with self._db() as db:
            rows = db.execute("SELECT body FROM audits ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [Audit.from_dict(json.loads(body)) for (body,) in rows]

    def delete_audit(self, audit_id: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM audits WHERE audit_id = ?", (audit_id,))

    # ----------------------------------------------------------------- backup
    def export_backup(self, include_terms: bool = True) -> Dict[str, Any]:
        """Rules, skill toggles and audit history. Never credentials, documents or document text."""
        rules = []
        for rule in self.list_rules():
            body = rule.to_dict()
            if not include_terms:
                body["terms"] = []
            rules.append(body)
        return {
            "backup_version": BACKUP_VERSION,
            "includes_terms": include_terms,
            "rules": rules,
            "skills": self.skill_states(),
            "audits": [a.to_dict() for a in self.list_audits(limit=1000)],
        }

    def import_backup(self, data: Dict[str, Any]) -> Dict[str, int]:
        """Merge a backup into this workspace (existing IDs are overwritten). Validates before writing."""
        if not isinstance(data, dict) or data.get("backup_version") != BACKUP_VERSION:
            raise ValueError("This is not a ShareSentry backup (unsupported or missing backup_version).")
        try:
            rules = [Rule.from_dict(r) for r in data.get("rules", [])]
            audits = [Audit.from_dict(a) for a in data.get("audits", [])]
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"The backup is malformed: {exc}") from None
        known = {s.name for s in SKILLS}
        states = {k: bool(v) for k, v in data.get("skills", {}).items() if k in known}
        for rule in rules:
            self.save_rule(rule)
        for audit in audits:
            self.save_audit(audit)
        for name, enabled in states.items():
            self.set_skill_enabled(name, enabled)
        return {"rules": len(rules), "audits": len(audits), "skills": len(states)}
