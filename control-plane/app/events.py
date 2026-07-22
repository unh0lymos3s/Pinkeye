"""Live run-event stream: the agent's reasoning, tool activity, findings, and memory changes as they
happen, so the chat UI can tail a run and reconnect to it.

This mirrors `app/audit.py` in shape but serves a different purpose. The audit log is the append-only
security record (every scope decision and tool execution, hashed for replay); run-events are the
*presentation* stream the operator watches. They carry summaries and prose only — never resolved
secrets or raw tool output — and, like audit events, are best-effort persisted to Postgres while an
in-memory buffer keeps SSE fast and lets a run degrade gracefully when Postgres is down.

Ordering guarantee: `seq` is a monotonic per-run counter assigned under a lock, so a reader can
replay a transcript and then tail everything after the last seq it saw with no gaps or dupes.
"""
from __future__ import annotations

import json
import queue
import threading
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Protocol

from pydantic import BaseModel, Field


class RunEventKind(str, Enum):
    plan = "plan"                # emitted once at start: stages, budget, authorized stages
    thinking = "thinking"        # the model's natural-language reasoning for a step
    tool_call = "tool_call"      # the model chose to run a tool (name, target, intensity, stage)
    tool_started = "tool_started"
    tool_finished = "tool_finished"
    finding = "finding"          # a normalized finding was recorded
    status = "status"            # run lifecycle: running / completed / failed / rejected
    memory_delta = "memory_delta"  # the network memory changed (new device, new/closed port, ...)
    refusal = "refusal"          # a model declined an authorized step; reinforce/fallback/final
    error = "error"              # a step failed (e.g. the LLM/provider was unreachable) — surfaced, not swallowed
    ask = "ask"                  # the agent is asking the operator a question (permission/recommendation)
    user_reply = "user_reply"    # the operator's reply, echoed into the transcript
    subagent_started = "subagent_started"    # the orchestrator delegated to a specialist sub-agent
    subagent_finished = "subagent_finished"  # a specialist sub-agent returned its summary


# A run is over once one of these terminal statuses is emitted; the SSE generator drains and closes.
TERMINAL_STATUSES = {"completed", "failed", "rejected"}


class RunEvent(BaseModel):
    engagement_id: str
    run_id: str
    seq: int
    kind: RunEventKind
    data: dict = Field(default_factory=dict)
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def is_terminal(self) -> bool:
        return self.kind == RunEventKind.status and self.data.get("status") in TERMINAL_STATUSES


class RunEventSink(Protocol):
    """What `run_agent(events=...)` needs: assign a seq, record the event, hand it back."""

    def emit(self, run_id: str, engagement_id: str, kind: str, /, **data) -> RunEvent: ...


class RunInbox:
    """Reverse channel for the interactive chat: the operator's reply travels from the `/reply`
    endpoint (request thread) to the run's background thread, which is blocked inside the `ask_user`
    tool waiting for a decision. One queue per run; thread-safe. This is the only path by which a
    human message re-enters a run — it carries guidance/permission, never authorization (the scope
    guard and flag gate still decide what any tool may do)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queues: dict[str, "queue.Queue[str]"] = {}

    def _q(self, run_id: str) -> "queue.Queue[str]":
        with self._lock:
            q = self._queues.get(run_id)
            if q is None:
                q = self._queues[run_id] = queue.Queue()
            return q

    def wait(self, run_id: str, timeout: float) -> Optional[str]:
        """Block the run thread until a reply arrives or `timeout` seconds pass (None on timeout)."""
        try:
            return self._q(run_id).get(timeout=timeout)
        except queue.Empty:
            return None

    def deliver(self, run_id: str, text: str) -> None:
        """Hand a reply to whichever run thread is (or will be) waiting."""
        self._q(run_id).put(text)


class MemoryRunEventSink:
    """Non-persistent sink for tests and single-process runs. Keeps a flat, ordered event list and a
    monotonic per-run seq — enough to assert emission order without a database."""

    def __init__(self) -> None:
        self.events: list[RunEvent] = []
        self._seq: dict[str, int] = {}

    def emit(self, run_id: str, engagement_id: str, kind: str, /, **data) -> RunEvent:
        # `run_id`/`engagement_id`/`kind` are positional-only so an event may carry data fields of the
        # same name (e.g. an ask_user prompt's `kind`) without a "multiple values" collision.
        self._seq[run_id] = self._seq.get(run_id, 0) + 1
        event = RunEvent(
            run_id=run_id, engagement_id=engagement_id, seq=self._seq[run_id],
            kind=RunEventKind(kind), data=data,
        )
        self.events.append(event)
        return event


class RunEventStore:
    """Production event store: monotonic per-run seq + a bounded in-memory ring buffer (the fast path
    for SSE tailing and reconnect) + best-effort Postgres persistence (durable, replayable).

    Everything is guarded by one lock because `emit` runs on the run's background thread while the SSE
    endpoint reads via `events_after` from the request/event-loop thread.
    """

    def __init__(self, db=None, buffer_size: int = 4000) -> None:
        self._db = db  # app.db.database.Database, or None for pure in-memory
        self._buffer_size = buffer_size
        self._lock = threading.Lock()
        self._seq: dict[str, int] = {}
        self._buffers: dict[str, deque[RunEvent]] = {}

    def emit(self, run_id: str, engagement_id: str, kind: str, /, **data) -> RunEvent:
        with self._lock:
            seq = self._seq.get(run_id, 0) + 1
            self._seq[run_id] = seq
            event = RunEvent(
                run_id=run_id, engagement_id=engagement_id, seq=seq,
                kind=RunEventKind(kind), data=data,
            )
            buf = self._buffers.get(run_id)
            if buf is None:
                buf = self._buffers[run_id] = deque(maxlen=self._buffer_size)
            buf.append(event)
        self._persist(event)  # outside the lock; a slow/broken DB must not stall emitters
        return event

    def events_after(self, run_id: str, after: int) -> list[RunEvent]:
        """Events with seq strictly greater than `after`, in order — the SSE tail primitive."""
        with self._lock:
            buf = self._buffers.get(run_id)
            if not buf:
                return []
            return [e for e in buf if e.seq > after]

    def all_events(self, run_id: str) -> list[RunEvent]:
        """Full transcript from the in-memory buffer, falling back to Postgres if this process never
        saw the run in memory (e.g. after an API restart)."""
        with self._lock:
            buf = self._buffers.get(run_id)
            if buf:
                return list(buf)
        return self._load(run_id)

    # ---- persistence (best-effort) ----

    def _persist(self, event: RunEvent) -> None:
        if self._db is None:
            return
        try:
            with self._db.connection() as conn:
                conn.execute(
                    "INSERT INTO run_events (run_id, engagement_id, seq, kind, data, at) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (
                        event.run_id, event.engagement_id, event.seq, event.kind.value,
                        json.dumps(event.data), event.at,
                    ),
                )
        except Exception:
            pass  # graceful degradation — the in-memory buffer still serves live tailing

    def _load(self, run_id: str) -> list[RunEvent]:
        if self._db is None:
            return []
        try:
            with self._db.connection() as conn:
                rows = conn.execute(
                    "SELECT run_id, engagement_id, seq, kind, data, at FROM run_events "
                    "WHERE run_id = %s ORDER BY seq",
                    (run_id,),
                ).fetchall()
        except Exception:
            return []
        return [
            RunEvent(run_id=r[0], engagement_id=r[1], seq=r[2], kind=RunEventKind(r[3]),
                     data=r[4], at=r[5])
            for r in rows
        ]
