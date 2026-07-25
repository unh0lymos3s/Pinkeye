"""Append-only audit event log.

Every scope decision, tool execution, and finding is recorded here so any run can be reconstructed
and defended after the fact. Events are never updated or deleted. Postgres is the store in
deployment; an in-memory sink keeps tests and the guard usable without a database.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Protocol, Sequence

from pydantic import BaseModel, Field


class EventType(str, Enum):
    scope_decision = "scope_decision"
    tool_started = "tool_started"
    tool_finished = "tool_finished"
    finding_recorded = "finding_recorded"
    run_status = "run_status"


class AuditEvent(BaseModel):
    engagement_id: str
    run_id: str
    type: EventType
    detail: str = ""
    tool: Optional[str] = None
    target: Optional[str] = None
    allowed: Optional[bool] = None  # set on scope_decision events
    output_sha256: Optional[str] = None  # hash of raw tool output, for replay integrity
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def hash_output(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode()
    return hashlib.sha256(raw).hexdigest()


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> None: ...

    def append_many(self, events: Sequence[AuditEvent]) -> None: ...


class MemoryAuditSink:
    """Non-persistent sink for tests and single-process runs."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)

    def append_many(self, events: Sequence[AuditEvent]) -> None:
        # `events or ()` so this sink is substitutable for PostgresAuditSink on an empty/None batch
        # too — the two are interchangeable through AuditSink, so they must agree on the edge cases.
        self.events.extend(events or ())


class PostgresAuditSink:
    """Persists events to the append-only audit_events table (created by migration 0003).

    Uses the shared connection pool and borrows a connection per append, so concurrent runs writing
    audit events from different background-task threads never share one connection (which psycopg
    forbids). The table's DDL lives in a migration, not here.
    """

    _INSERT = """
        INSERT INTO audit_events
            (engagement_id, run_id, type, detail, tool, target, allowed, output_sha256, at, payload)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    def __init__(self, db) -> None:
        self._db = db  # app.db.database.Database

    @staticmethod
    def _params(event: AuditEvent) -> tuple:
        return (
            event.engagement_id,
            event.run_id,
            event.type.value,
            event.detail,
            event.tool,
            event.target,
            event.allowed,
            event.output_sha256,
            event.at,
            json.dumps(event.model_dump(mode="json")),
        )

    def append(self, event: AuditEvent) -> None:
        with self._db.connection() as conn:
            conn.execute(self._INSERT, self._params(event))

    def append_many(self, events: Sequence[AuditEvent]) -> None:
        """Write a whole step's events in one borrowed connection / one transaction. The
        append-only guarantee is unaffected: rows are still never updated or deleted."""
        rows = [self._params(e) for e in events or ()]
        if not rows:
            return
        with self._db.connection() as conn:
            with conn.cursor() as cur:
                cur.executemany(self._INSERT, rows)
