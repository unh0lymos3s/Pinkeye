"""Retention (§4), the durable tail fallback (C6) and the wake primitive (B4) for the run-event
stream and the cross-run memory.

Everything here runs against a fake `Database` so the durable half of each contract is actually
exercised: retention is only safe *because* a durable copy exists, and the tests assert exactly that
— an evicted buffer still replays from `run_events`, an evicted per-run delta still replays from
`network_observations`, and the seq counter never restarts under a reader's feet.
"""
import json
import threading
import time
from types import SimpleNamespace

from app.events import RunEventStore, RunInbox
from app.memory import NetworkMemory
from app.models import Finding, FindingState, Severity


# ---- fakes -------------------------------------------------------------------------------------

class _Result:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _Cursor:
    def __init__(self, db):
        self._db = db

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def executemany(self, sql, rows):
        for row in rows:
            self._db.execute(sql, row)


class _Conn:
    def __init__(self, db):
        self._db = db

    def execute(self, sql, params=()):
        return self._db.execute(sql, params)

    def cursor(self):
        return _Cursor(self._db)


class _ConnCtx:
    def __init__(self, db):
        self._db = db

    def __enter__(self):
        return _Conn(self._db)

    def __exit__(self, *exc):
        return False


class FakeDb:
    """Minimal stand-in for `app.db.database.Database`: enough SQL to serve run_events and
    network_observations, plus a counter so a test can prove the read path is not per-poll."""

    def __init__(self):
        self.run_events = []      # (run_id, engagement_id, seq, kind, data_json, at)
        self.observations = []    # (engagement_id, run_id, kind, key, change, before, after)
        self.selects = 0

    def connection(self):
        return _ConnCtx(self)

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        if sql.startswith("INSERT INTO run_events"):
            self.run_events.append(tuple(params))
            return _Result([])
        if sql.startswith("INSERT INTO network_observations"):
            self.observations.append(tuple(params))
            return _Result([])
        if sql.startswith("SELECT run_id, engagement_id, seq, kind, data, at FROM run_events"):
            self.selects += 1
            rows = [(r[0], r[1], r[2], r[3], json.loads(r[4]), r[5])
                    for r in self.run_events if r[0] == params[0]]
            return _Result(sorted(rows, key=lambda r: r[2]))
        if sql.startswith("SELECT kind, key, change, before, after FROM network_observations"):
            self.selects += 1
            rows = [(o[2], o[3], o[4],
                     json.loads(o[5]) if o[5] else None,
                     json.loads(o[6]) if o[6] else None)
                    for o in self.observations if o[1] == params[0]]
            return _Result(rows)
        if sql.startswith("SELECT DISTINCT key FROM network_observations"):
            self.selects += 1
            keys = sorted({o[3] for o in self.observations
                           if o[0] == params[0] and o[2] == "endpoint"
                           and o[4] == "newly_exploitable"})
            return _Result([(k,) for k in keys])
        raise AssertionError(f"unexpected SQL: {sql}")


class FakeGraph:
    """Graph stub exposing only `load_devices`, which is the capability state retention is gated on."""

    def __init__(self, devices=None, delay=0.0):
        self.devices = devices or []
        self.delay = delay
        self.calls_for = []

    @property
    def calls(self):
        return len(self.calls_for)

    def load_devices(self, engagement_id):
        self.calls_for.append(engagement_id)
        if self.delay:
            time.sleep(self.delay)
        return list(self.devices)


def svc(address, port, proto="tcp", service="", product=""):
    return SimpleNamespace(address=address, port=port, proto=proto, service=service, product=product)


def finding(target, category="sql-injection", severity=Severity.critical,
            state=FindingState.confirmed):
    return Finding(id="f", engagement_id="e1", run_id="r", title="t", category=category,
                   severity=severity, state=state, target=target)


# ---- B4: O(new events) tailing + the wake primitive --------------------------------------------

def test_events_after_is_arithmetic_and_steady_state_is_empty():
    store = RunEventStore(db=None, buffer_size=3)
    for i in range(6):
        store.emit("r1", "e1", "thinking", text=str(i))
    # maxlen=3, so the ring now holds seq 4,5,6 and buf[0].seq is no longer 1.
    assert [e.seq for e in store.events_after("r1", 5)] == [6]
    assert store.events_after("r1", 6) == []       # steady state: nothing copied
    assert [e.seq for e in store.events_after("r1", 3)] == [4, 5, 6]
    # A reader further behind than the ring start gets everything still buffered rather than nothing,
    # because with db=None there is no durable log to recover the dropped seqs from.
    assert [e.seq for e in store.events_after("r1", 1)] == [4, 5, 6]


def test_buffer_wrap_falls_back_to_the_durable_log_with_no_gaps():
    db = FakeDb()
    store = RunEventStore(db=db, buffer_size=3)
    for i in range(6):
        store.emit("r1", "e1", "thinking", text=str(i))
    # The ring dropped 1..3; the durable log still has them, so a lagging reader gets a gapless tail.
    assert [e.seq for e in store.events_after("r1", 1)] == [2, 3, 4, 5, 6]
    # And a reader inside the ring is still served from memory (no query for this call).
    before = db.selects
    assert [e.seq for e in store.events_after("r1", 5)] == [6]
    assert db.selects == before


def test_waiter_is_set_by_emit_and_shared_per_run():
    store = RunEventStore(db=None)
    waiter = store.waiter("r1")
    assert store.waiter("r1") is waiter          # one handle per run
    assert not waiter.is_set()
    store.emit("r1", "e1", "thinking", text="hi")
    assert waiter.is_set()
    waiter.clear()
    store.emit("r2", "e1", "thinking", text="other run")
    assert not waiter.is_set()                   # another run's emit does not wake this tail


# ---- C6: the durable fallback must not become a per-poll query storm ---------------------------

def test_durable_tail_snapshot_is_shared_between_polls():
    db = FakeDb()
    producer = RunEventStore(db=db)              # stands in for the process that owns the run
    for i in range(3):
        producer.emit("remote-run", "e1", "thinking", text=str(i))

    reader = RunEventStore(db=db)                # a second process: no in-memory buffer at all
    db.selects = 0
    tails = [reader.events_after("remote-run", 0) for _ in range(6)]
    assert all([e.seq for e in t] == [1, 2, 3] for t in tails)
    # Six polls, one query: the snapshot is loaded once per window and shared by every tail.
    assert db.selects == 1


# ---- §4: retention ----------------------------------------------------------------------------

def test_terminal_run_is_retired_but_stays_replayable_and_seq_never_restarts():
    db = FakeDb()
    store = RunEventStore(db=db, retention_seconds=0.0)
    retired = []
    store.on_retire(retired.append)
    for i in range(3):
        store.emit("r1", "e1", "thinking", text=str(i))
    store.emit("r1", "e1", "status", status="completed")
    assert "r1" in store._buffers                # the emitting run is never swept by its own emit

    store.emit("r2", "e1", "plan")               # any later activity sweeps the expired run
    assert retired == ["r1"]
    assert "r1" not in store._buffers and "r1" not in store._seq

    # The transcript and the tail both still answer, from `run_events`.
    assert [e.seq for e in store.all_events("r1")] == [1, 2, 3, 4]
    assert [e.seq for e in store.events_after("r1", 2)] == [3, 4]

    # A late post-terminal event resumes the counter instead of colliding with the durable rows.
    assert store.emit("r1", "e1", "thinking", text="late").seq == 5


def test_retention_is_a_no_op_without_a_database():
    store = RunEventStore(db=None, retention_seconds=0.0)
    store.emit("r1", "e1", "status", status="completed")
    store.emit("r2", "e1", "plan")
    # No durable copy exists, so evicting would destroy the only record of the transcript.
    assert [e.seq for e in store.all_events("r1")] == [1]
    assert "r1" in store._buffers


def test_inbox_sweeps_idle_empty_queues_but_never_an_undelivered_reply():
    box = RunInbox(retention_seconds=0.0)
    box.deliver("r1", "hello")
    box.deliver("r2", "world")
    assert box.wait("r1", 0.01) == "hello"       # r1's queue is now empty and idle
    box.wait("r3", 0.0)                          # any use runs the sweep
    assert "r1" not in box._queues
    assert box.wait("r2", 0.01) == "world"       # an undelivered reply survived the sweep
    box.retire("r2")
    assert "r2" not in box._queues


def test_inbox_never_sweeps_a_queue_a_run_thread_is_blocked_on():
    # The dangerous shape: the sweep drops the object the run thread is parked on, `deliver` then
    # creates a fresh queue, and the operator's reply is silently lost until the ask_user timeout.
    box = RunInbox(retention_seconds=0.0)
    got = []

    def run_thread():
        got.append(box.wait("r1", 2.0))

    waiter = threading.Thread(target=run_thread)
    waiter.start()
    deadline = time.monotonic() + 1.0
    while "r1" not in box._waiting and time.monotonic() < deadline:
        time.sleep(0.005)
    assert box._waiting.get("r1") == 1

    for i in range(5):                            # plenty of unrelated traffic, each one sweeping
        box.wait(f"other-{i}", 0.0)
    assert "r1" in box._queues

    box.deliver("r1", "approved, proceed")
    waiter.join(2.0)
    assert got == ["approved, proceed"]
    assert "r1" not in box._waiting               # the waiter count unwinds
    box.wait("noise", 0.0)                        # ...and the now-idle queue is finally swept
    assert "r1" not in box._queues


def test_memory_retires_run_deltas_and_replays_them_from_the_diff_log():
    db = FakeDb()
    mem = NetworkMemory(graph=None, db=db, retention_seconds=0.0)
    mem.observe("e1", "run1", [svc("10.0.0.5", 22, service="ssh")], [])
    mem.observe("e1", "run2", [svc("10.0.0.6", 443)], [])
    assert "run1" not in mem._run_deltas

    agg = mem.deltas_for_run("run1")             # C7: reconstructed from network_observations
    keys = {e["key"] for e in agg.added}
    assert keys == {"10.0.0.5", "10.0.0.5:22/tcp"}
    assert any("new service" in e["label"] for e in agg.added)


def test_memory_retention_is_a_no_op_without_a_database():
    mem = NetworkMemory(retention_seconds=0.0)
    mem.observe("e1", "run1", [svc("10.0.0.5", 22)], [])
    mem.observe("e1", "run2", [svc("10.0.0.6", 443)], [])
    assert "run1" in mem._run_deltas             # nothing durable to replay it from


def test_memory_state_is_retired_and_rewarmed_from_the_graph():
    graph = FakeGraph(devices=[{
        "address": "10.0.0.5", "status": "active",
        "services": [{"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH 8.0"}],
    }])
    mem = NetworkMemory(graph=graph, db=None, state_ttl_seconds=0.0)
    mem.observe("e1", "run1", [svc("10.0.0.5", 22, service="ssh", product="OpenSSH 8.0")], [])
    # The engagement this call is writing to survives its own sweep, whatever the TTL.
    assert graph.calls_for == ["e1"] and "e1" in mem._state

    mem.observe("e2", "run2", [svc("10.0.0.9", 80)], [])   # sweeps the now-idle e1
    assert "e1" not in mem._state and "e2" in mem._state

    # Re-warmed from the graph, so the previously-known service is still known: no false "new".
    assert mem.observe("e1", "run3",
                       [svc("10.0.0.5", 22, service="ssh", product="OpenSSH 8.0")], []).is_empty()
    assert graph.calls_for == ["e1", "e2", "e1"]


def test_rewarmed_state_does_not_re_report_a_known_exploitable_endpoint():
    db = FakeDb()
    mem = NetworkMemory(graph=FakeGraph(), db=db, state_ttl_seconds=0.0)
    first = mem.observe("e1", "run1", [], [finding("https://app.example.com/login")])
    assert any(e["kind"] == "endpoint" for e in first.newly_exploitable)

    mem.observe("e2", "run2", [], [])                      # sweeps e1
    assert "e1" not in mem._state

    # The graph cannot replay endpoints, so the diff log is what keeps this idempotent.
    again = mem.observe("e1", "run3", [], [finding("https://app.example.com/login")])
    assert not again.newly_exploitable


# ---- B10b: warm-up is serialized per engagement -------------------------------------------------

def test_concurrent_ensure_loaded_warms_once_and_never_exposes_a_half_built_map():
    graph = FakeGraph(devices=[{"address": "10.0.0.5", "status": "active", "services": [
        {"port": p, "proto": "tcp", "service": "x", "product": ""} for p in range(20)
    ]}], delay=0.05)
    mem = NetworkMemory(graph=graph)
    seen = []

    def work():
        snap = mem.snapshot("e1")
        seen.append(len(snap["devices"][0]["services"]))

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert graph.calls == 1          # one warm, not eight
    assert seen == [20] * 8          # nobody observed a partially populated device
