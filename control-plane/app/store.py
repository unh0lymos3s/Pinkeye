"""In-memory engagement/run store for Phase 1.

Postgres-backed persistence arrives with the multi-tenant work in Phase 7; the audit log already
persists to Postgres. Keeping this in memory lets the single-host stack run without migrations.
"""
from __future__ import annotations

from .models import Engagement, Run


class Store:
    def __init__(self) -> None:
        self.engagements: dict[str, Engagement] = {}
        self.runs: dict[str, Run] = {}

    def add_engagement(self, engagement: Engagement) -> None:
        self.engagements[engagement.id] = engagement

    def add_run(self, run: Run) -> None:
        self.runs[run.id] = run
