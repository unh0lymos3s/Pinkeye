"""Durable job queue backed by Postgres.

Runs are enqueued instead of executed in-process, so workers scale horizontally and jobs survive an
API restart. Claiming uses FOR UPDATE SKIP LOCKED — the standard pattern for many workers draining one
queue without double-processing.
"""
from __future__ import annotations

import json
import uuid

from .db.database import Database


class JobQueue:
    def __init__(self, db: Database):
        self._db = db

    def enqueue(self, tenant_id: str, engagement_id: str, payload: dict) -> str:
        job_id = str(uuid.uuid4())
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO jobs (id, tenant_id, engagement_id, payload, status) "
                "VALUES (%s, %s, %s, %s, 'queued')",
                (job_id, tenant_id, engagement_id, json.dumps(payload)),
            )
        return job_id

    def claim(self) -> dict | None:
        """Atomically take the oldest queued job and mark it running. Returns None if the queue is empty."""
        with self._db.connection() as conn:
            with conn.transaction():
                row = conn.execute(
                    "SELECT id, tenant_id, engagement_id, payload FROM jobs "
                    "WHERE status = 'queued' ORDER BY created_at "
                    "FOR UPDATE SKIP LOCKED LIMIT 1"
                ).fetchone()
                if not row:
                    return None
                conn.execute(
                    "UPDATE jobs SET status = 'running', claimed_at = now() WHERE id = %s", (row[0],)
                )
        return {"id": row[0], "tenant_id": row[1], "engagement_id": row[2], "payload": row[3]}

    def finish(self, job_id: str, ok: bool) -> None:
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE jobs SET status = %s WHERE id = %s", ("done" if ok else "failed", job_id)
            )
