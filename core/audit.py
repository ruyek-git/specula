"""Structured audit log.

Every decision and action is recorded as a structured row BEFORE the action
runs. LLM reasoning is opaque, so we do not rely on it for accountability - the
audit log is the evidence. The model's natural-language rationale is stored too,
but as commentary, not as the record of what happened.

Backed by SQLite so the repo has zero external dependencies and the log is
queryable with plain SQL during a post-incident review.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AuditRecord:
    alert_id: str
    stage: str            # triage | enrichment | correlation | gate | action
    decision: str         # e.g. "route_human", "autonomous", "disabled_detection"
    severity: str
    confidence: float
    detail: dict          # inputs seen, tool calls, results, rationale
    ts: float


class AuditLog:
    def __init__(self, path: str = "specula_audit.db"):
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                alert_id TEXT NOT NULL,
                stage TEXT NOT NULL,
                decision TEXT NOT NULL,
                severity TEXT,
                confidence REAL,
                detail TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def record(
        self,
        alert_id: str,
        stage: str,
        decision: str,
        detail: dict,
        severity: str = "",
        confidence: float = 0.0,
    ) -> None:
        self._conn.execute(
            "INSERT INTO audit (ts, alert_id, stage, decision, severity, confidence, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                time.time(),
                alert_id,
                stage,
                decision,
                severity,
                confidence,
                json.dumps(detail, default=str),
            ),
        )
        self._conn.commit()

    def for_alert(self, alert_id: str) -> list[AuditRecord]:
        cur = self._conn.execute(
            "SELECT alert_id, stage, decision, severity, confidence, detail, ts "
            "FROM audit WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        )
        return [
            AuditRecord(
                alert_id=r[0],
                stage=r[1],
                decision=r[2],
                severity=r[3],
                confidence=r[4],
                detail=json.loads(r[5]),
                ts=r[6],
            )
            for r in cur.fetchall()
        ]

    def close(self) -> None:
        self._conn.close()


def reset(path: str = "specula_audit.db") -> None:
    """Drop the audit DB - convenience for repeatable demos."""
    p = Path(path)
    if p.exists():
        p.unlink()
