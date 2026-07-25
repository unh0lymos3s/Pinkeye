"""Live run-event stream: the agent's reasoning, tool activity, findings, and memory changes as they
happen, so the chat UI can tail a run and reconnect to it.

This mirrors `app/audit.py` in shape but serves a different purpose. The audit log is the append-only
security record (every scope decision and tool execution, hashed for replay); run-events are the
*presentation* stream the operator watches. They carry summaries and prose only — never resolved
secrets or raw tool output — and, like audit events, are best-effort persisted to Postgres while an
in-memory buffer keeps SSE fast and lets a run degrade gracefully when Postgres is down.

Ordering guarantee: `seq` is a monotonic per-run counter assigned under a lock, so a reader can
replay a transcript and then tail everything after the last seq it saw with no gaps or dupes.

Retention (§4): this process is designed to run for weeks, so none of the per-run state here may be
kept forever. Every structure keyed by `run_id` is retired a configurable grace period after the run
emits its terminal status — long enough that a client reconnecting just after completion is still
served from memory, after which the durable `run_events` table answers instead. Retention is a
**no-op when no database is wired** (`db=None`, the pure in-memory test/dev sink): with no durable
copy, evicting a buffer would destroy the only record of the transcript.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from bisect import bisect_right
from collections import OrderedDict, deque
from datetime import datetime, timezone
from enum import Enum
from itertools import islice
from typing import Callable, Optional, Protocol

from pydantic import BaseModel, Field

from .envknobs import env_float


# §4 — how long a run's in-memory state (event buffer, seq counter, wake handle, inbox queue) is kept
# after its terminal status. A reconnect inside this window is served from memory; after it, from
# Postgres. 0 retires as soon as the next event is emitted anywhere.
RUN_RETENTION_SECONDS = env_float("EYE_RUN_RETENTION_SECONDS", 3600.0)

# C6 — minimum spacing between durable-log reads for one run that has no in-memory buffer. Without
# it, *every* SSE heartbeat of *every* client tailing such a run is its own `SELECT ... run_events`,
# which turns a graceful degradation into a per-poll query storm. The snapshot is shared between all
# tails of that run for the window, so the read cost is bounded per run rather than per client.
_TAIL_SNAPSHOT_TTL_SECONDS = env_float("EYE_RUN_TAIL_DB_INTERVAL", 2.0)
# ...and a hard cap on how many such snapshots are held, since a transcript is not small and the
# run_id comes from the URL (an unknown id must not be able to grow this without bound).
_TAIL_SNAPSHOT_MAX_RUNS = 32
# A retired run keeps *only* its last seq, capped and in retirement order. See `emit`: dropping the
# counter outright would let a late post-terminal event restart at seq=1 and collide with the durable
# (run_id, seq) rows a reconnecting client replays. An int per run is cheap; the buffer is not.
_RETIRED_SEQ_MAX = 8192


def _tail_after(events: list[RunEvent], after: int) -> list[RunEvent]:
    """Everything with `seq > after` from a seq-ordered list, located by bisection.

    Used on the durable-log path, where the rows arrive `ORDER BY seq`. Bisecting rather than
    filtering keeps the steady state (nothing new) O(log n) with no copy, matching the in-memory
    path — and it cannot reorder or drop, so the no-gaps/no-dupes contract is unaffected.
    """
    start = bisect_right(events, after, key=lambda e: e.seq)
    if start >= len(events):
        return []
    return events[start:]


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
    guard and flag gate still decide what any tool may do).

    §4: one queue per run, for every run the process has ever seen, is unbounded growth. Queues are
    therefore retired either explicitly (`retire`, wired to the event store's terminal-status hook)
    or by an idle sweep on use. A queue is only ever dropped when it is **empty and nobody is blocked
    on it**, which is what makes this lossless: `_q` recreates one on demand, and such a queue holds
    no reply anybody could still read. Dropping a queue with a waiter would be a *silent* bug —
    `deliver` would create a fresh queue and put the operator's text into it while the run thread sat
    on the old object until its `ask_user` timeout — so the waiter count is tracked explicitly rather
    than inferred from the retention window being longer than the ask timeout.
    """

    def __init__(self, retention_seconds: float | None = None) -> None:
        self._lock = threading.Lock()
        self._queues: dict[str, "queue.Queue[str]"] = {}
        # run_id -> monotonic time of last use, in touch order, so the sweep stops at the first live
        # entry instead of walking every run this process has ever seen.
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        # run_id -> number of run threads currently blocked in `wait`.
        self._waiting: dict[str, int] = {}
        self._retention = RUN_RETENTION_SECONDS if retention_seconds is None else retention_seconds

    def _q(self, run_id: str, waiting: bool = False) -> "queue.Queue[str]":
        now = time.monotonic()
        with self._lock:
            q = self._queues.get(run_id)
            if q is None:
                q = self._queues[run_id] = queue.Queue()
            if waiting:
                # Registered before the lock is released, so no sweep can see this queue as idle
                # between here and the caller blocking on it.
                self._waiting[run_id] = self._waiting.get(run_id, 0) + 1
            self._seen[run_id] = now
            self._seen.move_to_end(run_id)
            self._sweep(now)
            return q

    def _sweep(self, now: float) -> None:
        """Drop idle queues that are empty and unwatched. Caller holds `self._lock`.

        A queue holding an undelivered reply, or with a run thread parked on it, is re-armed rather
        than dropped — the operator's text is the one thing in this module that cannot be
        reconstructed from anywhere else.
        """
        while self._seen:
            run_id, seen = next(iter(self._seen.items()))
            if now - seen <= self._retention:
                # Touch-ordered, so everything behind this entry is younger still. `<=` rather than
                # `<` so the entry the caller just touched can never be swept out from under the very
                # call that is about to use its queue (which `retention = 0` would otherwise do).
                break
            q = self._queues.get(run_id)
            if q is not None and (not q.empty() or self._waiting.get(run_id)):
                self._seen[run_id] = now  # still in use: reconsider it a window from now
                self._seen.move_to_end(run_id)
            else:
                self._queues.pop(run_id, None)
                self._seen.pop(run_id, None)

    def retire(self, run_id: str) -> None:
        """Forget a finished run's queue. Safe to call for an unknown run.

        Intended for `RunEventStore.on_retire`, i.e. a full retention window *after* the run's
        terminal status, by which point no run thread can still be inside `wait` — but the waiter
        check is enforced rather than assumed, for the same reason as in `_sweep`."""
        with self._lock:
            if self._waiting.get(run_id):
                return
            self._queues.pop(run_id, None)
            self._seen.pop(run_id, None)

    def wait(self, run_id: str, timeout: float) -> Optional[str]:
        """Block the run thread until a reply arrives or `timeout` seconds pass (None on timeout)."""
        q = self._q(run_id, waiting=True)
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None
        finally:
            with self._lock:
                remaining = self._waiting.get(run_id, 1) - 1
                if remaining > 0:
                    self._waiting[run_id] = remaining
                else:
                    self._waiting.pop(run_id, None)

    def deliver(self, run_id: str, text: str) -> None:
        """Hand a reply to whichever run thread is (or will be) waiting."""
        self._q(run_id).put(text)


class RunEventStore:
    """Production event store: monotonic per-run seq + a bounded in-memory ring buffer (the fast path
    for SSE tailing and reconnect) + best-effort Postgres persistence (durable, replayable).

    Everything is guarded by one lock because `emit` runs on the run's background thread while the SSE
    endpoint reads via `events_after` from the request/event-loop thread.
    """

    def __init__(self, db=None, buffer_size: int = 4000,
                 retention_seconds: float | None = None) -> None:
        self._db = db  # app.db.database.Database, or None for pure in-memory
        self._buffer_size = buffer_size
        self._lock = threading.Lock()
        self._seq: dict[str, int] = {}
        self._buffers: dict[str, deque[RunEvent]] = {}
        # One waiter per run, set by `emit` so SSE tails wake on a new event instead of polling.
        self._waiters: dict[str, threading.Event] = {}
        # --- §4 retention state ---
        self._retention = RUN_RETENTION_SECONDS if retention_seconds is None else retention_seconds
        # run_id -> monotonic deadline, in deadline order (the grace period is constant, so insertion
        # order *is* deadline order and the sweep stops at the first entry that is still live).
        self._retire_at: "OrderedDict[str, float]" = OrderedDict()
        # run_id -> last assigned seq, for runs whose buffer has already been dropped.
        self._retired_seq: "OrderedDict[str, int]" = OrderedDict()
        self._retire_hooks: list[Callable[[str], None]] = []
        # C6 — run_id -> (monotonic load time, seq-ordered durable snapshot).
        self._tail_snapshots: dict[str, tuple[float, list[RunEvent]]] = {}

    # ---- emit / tail ----

    def emit(self, run_id: str, engagement_id: str, kind: str, /, **data) -> RunEvent:
        now = time.monotonic()
        with self._lock:
            # This run is emitting, so it is not a retirement candidate. Cancelling any pending
            # deadline *before* the sweep is what guarantees the sweep can never drop the buffer this
            # call is about to append to.
            self._retire_at.pop(run_id, None)
            # Opportunistic, on the thread that already holds the lock: no timer thread, so there is
            # no shutdown story to get wrong and no sweep racing a torn-down process.
            retired = self._collect_retired(now)
            prev = self._seq.get(run_id)
            if prev is None:
                # A run whose buffer was already retired must resume its counter, not restart it: the
                # durable rows for seq 1..N still exist and a reconnecting client replays them, so a
                # second seq=1 would be both a dupe for that reader and a duplicate key in Postgres.
                prev = self._retired_seq.pop(run_id, 0)
            seq = prev + 1
            self._seq[run_id] = seq
            event = RunEvent(
                run_id=run_id, engagement_id=engagement_id, seq=seq,
                kind=RunEventKind(kind), data=data,
            )
            buf = self._buffers.get(run_id)
            if buf is None:
                buf = self._buffers[run_id] = deque(maxlen=self._buffer_size)
            buf.append(event)
            if event.is_terminal():
                self._schedule_retire(run_id, now)
            waiter = self._waiters.get(run_id)
        if waiter is not None:
            waiter.set()  # wake every tail on this run; they re-clear before their next drain
        # Both of these are outside the lock: a slow/broken DB (and an arbitrary hook) must not stall
        # emitters, and a hook reaching into RunInbox/NetworkMemory must not invert lock order.
        self._notify_retired(retired)
        self._persist(event)
        return event

    def waiter(self, run_id: str) -> threading.Event:
        """The wakeup handle for a run (B4). A reader clears it, drains with `events_after`, then
        blocks on `wait(timeout)`; `emit` sets it, so latency is ~0 and an idle tail costs no CPU.
        Clearing before draining is what makes an emit racing the drain a spurious wakeup rather than
        a lost one.

        Safe to call before any event exists for the run. Retention never takes a live run's waiter:
        a run is only a retirement candidate once it has emitted a terminal status, and any
        non-terminal emit cancels that. A handle created for a run this process never sees emit (an
        unknown id, or a run executing in another process) *is* eventually swept — the tail then
        degrades to its heartbeat interval and re-registers on the next call, which is exactly the
        pre-B4 behaviour rather than a hang.
        """
        now = time.monotonic()
        with self._lock:
            retired = self._collect_retired(now)
            w = self._waiters.get(run_id)
            if w is None:
                w = self._waiters[run_id] = threading.Event()
                if run_id not in self._seq:
                    # A handle for a run this process has never emitted for. The run_id comes from the
                    # URL, so without a deadline an unknown id would register an Event forever.
                    self._schedule_retire(run_id, now)
        self._notify_retired(retired)
        return w

    def events_after(self, run_id: str, after: int) -> list[RunEvent]:
        """Events with seq strictly greater than `after`, in order — the SSE tail primitive.

        B4: `seq` is dense and monotonic per run and the deque is append-ordered, so the starting
        offset is arithmetic. The old filter compared all 4 000 buffered events on every tick of
        every client, under the same lock `emit` needs — a watched run slowed the run being watched.
        C6: when this process never saw the run (an API restart, or a run executing elsewhere) the
        durable log answers instead of returning nothing forever.
        """
        with self._lock:
            buf = self._buffers.get(run_id)
            if buf:
                first = buf[0].seq
                if after >= first - 1:
                    start = after - first + 1
                    if start >= len(buf):
                        return []
                    return list(islice(buf, start, None))
                if self._db is None:
                    # The ring dropped events older than `after + 1` and there is no durable log to
                    # recover them from; hand back everything still buffered rather than nothing.
                    return list(buf)
            elif self._db is None:
                return []
        # C6 — durable path: either no buffer at all, or the ring has already evicted `after + 1`.
        events = self._tail_snapshot(run_id)
        tail = _tail_after(events, after)
        if tail or buf is None:
            return tail
        # The buffer has events beyond `after` but the durable log does not — a `_persist` that
        # failed for exactly those seqs, since persistence is best-effort by design. Serving the
        # buffer accepts an unrecoverable gap instead of stalling the tail on it forever. Still no
        # dupes: every event handed back has seq > after.
        with self._lock:
            live = self._buffers.get(run_id)
            return list(live) if live else []

    def all_events(self, run_id: str) -> list[RunEvent]:
        """Full transcript from the in-memory buffer, falling back to Postgres if this process never
        saw the run in memory (e.g. after an API restart, or once the buffer has been retired)."""
        with self._lock:
            buf = self._buffers.get(run_id)
            if buf:
                return list(buf)
        return self._load(run_id)

    # ---- retention (§4) ----

    def on_retire(self, hook: Callable[[str], None]) -> None:
        """Register a callback invoked with a run_id once its in-memory state is dropped, so the
        other per-run structures in the process (`RunInbox._queues`, `NetworkMemory._run_deltas`,
        `Store.runs`) retire on the same schedule, off the same terminal-status signal.

        Hooks run outside the store lock and their exceptions are swallowed: retention is
        housekeeping and must never fail an emit.
        """
        with self._lock:
            self._retire_hooks.append(hook)

    def _schedule_retire(self, run_id: str, now: float) -> None:
        """Mark a run for cleanup one grace period from now. Caller holds `self._lock`.

        Retention is a deliberate no-op without a database: `run_events` is the durable copy that
        makes dropping a buffer free, and `RunEventStore(db=None)` (the test/dev sink) has none.
        """
        if self._db is None:
            return
        self._retire_at.pop(run_id, None)  # re-arm, keeping the map in deadline order
        self._retire_at[run_id] = now + self._retention

    def _collect_retired(self, now: float) -> list[str]:
        """Drop every run whose grace period has elapsed. Caller holds `self._lock`."""
        if self._db is None or not self._retire_at:
            return []
        dropped: list[str] = []
        while self._retire_at:
            run_id, deadline = next(iter(self._retire_at.items()))
            if deadline > now:
                break
            self._retire_at.pop(run_id, None)
            self._buffers.pop(run_id, None)
            self._waiters.pop(run_id, None)
            self._tail_snapshots.pop(run_id, None)
            seq = self._seq.pop(run_id, None)
            if seq is not None:
                self._retired_seq[run_id] = seq
                self._retired_seq.move_to_end(run_id)
                while len(self._retired_seq) > _RETIRED_SEQ_MAX:
                    self._retired_seq.popitem(last=False)
            dropped.append(run_id)
        return dropped

    def _notify_retired(self, run_ids: list[str]) -> None:
        if not run_ids:
            return
        with self._lock:
            hooks = list(self._retire_hooks)
        for run_id in run_ids:
            for hook in hooks:
                try:
                    hook(run_id)
                except Exception:
                    pass  # housekeeping never fails an emit

    # ---- durable log: fallback reads + best-effort writes ----

    def _tail_snapshot(self, run_id: str) -> list[RunEvent]:
        """A seq-ordered durable snapshot of a run, at most `_TAIL_SNAPSHOT_TTL_SECONDS` old.

        C6's fallback is only useful if it is cheap enough to sit under an SSE tail. Each snapshot is
        loaded once per window and shared by every client tailing that run, so the durable read rate
        is bounded per run instead of scaling with the number of watchers. It is deliberately *not*
        written into `_buffers`: a run executing in another process keeps appending, and a permanent
        in-memory copy would make the arithmetic fast path answer from a frozen transcript forever.
        """
        now = time.monotonic()
        with self._lock:
            cached = self._tail_snapshots.get(run_id)
            if cached is not None and now - cached[0] < _TAIL_SNAPSHOT_TTL_SECONDS:
                return cached[1]
            # Reserve the window *before* releasing the lock so concurrent tails on the same run
            # serve the previous snapshot for one window rather than all issuing the same query.
            self._tail_snapshots[run_id] = (now, cached[1] if cached else [])
            self._prune_snapshots(now)
        events = self._load(run_id)  # outside the lock: a slow DB must not stall emit
        with self._lock:
            reserved = self._tail_snapshots.get(run_id)
            # Keep the reservation timestamp so a slow query does not extend the window past it.
            self._tail_snapshots[run_id] = (reserved[0] if reserved else now, events)
        return events

    def _prune_snapshots(self, now: float) -> None:
        """Keep the snapshot cache bounded. Caller holds `self._lock`."""
        if len(self._tail_snapshots) <= _TAIL_SNAPSHOT_MAX_RUNS:
            return
        for run_id, (loaded_at, _) in list(self._tail_snapshots.items()):
            if now - loaded_at >= _TAIL_SNAPSHOT_TTL_SECONDS:
                self._tail_snapshots.pop(run_id, None)
        while len(self._tail_snapshots) > _TAIL_SNAPSHOT_MAX_RUNS:
            oldest = min(self._tail_snapshots, key=lambda r: self._tail_snapshots[r][0])
            self._tail_snapshots.pop(oldest, None)

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


class MemoryRunEventSink(RunEventStore):
    """Non-persistent sink for tests and single-process runs.

    R3: this used to be a second, parallel implementation of `emit` — same `RunEvent` construction,
    same per-run seq counter. `RunEventStore(db=None)` already *is* the pure in-memory sink, so the
    duplicate is gone and only the one thing this type adds remains: a flat, cross-run, unbounded
    event list, which is what makes `sink.events[-1]` and "assert the whole emission order" readable
    in tests. The store's own buffers are per-run and bounded, so they cannot serve that.
    """

    def __init__(self) -> None:
        super().__init__(db=None)
        self.events: list[RunEvent] = []

    def emit(self, run_id: str, engagement_id: str, kind: str, /, **data) -> RunEvent:
        event = super().emit(run_id, engagement_id, kind, **data)
        self.events.append(event)
        return event
