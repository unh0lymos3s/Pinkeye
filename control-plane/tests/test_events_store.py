"""RunEventStore ordering guarantees + a TestClient smoke of the chat endpoints (transcript, one SSE
frame, memory, changes). The store runs db=None so it's a pure in-memory ring buffer here."""
from app.events import RunEventKind, RunEventStore


def test_seq_is_monotonic_per_run_and_events_after_tails():
    store = RunEventStore(db=None)
    for i in range(5):
        store.emit("r1", "e1", "thinking", text=f"t{i}")
    assert [e.seq for e in store.all_events("r1")] == [1, 2, 3, 4, 5]
    assert [e.seq for e in store.events_after("r1", 3)] == [4, 5]
    # A different run has an independent monotonic sequence.
    first = store.emit("r2", "e1", "plan")
    assert first.seq == 1


def test_terminal_status_detection():
    store = RunEventStore(db=None)
    assert store.emit("r1", "e1", "status", status="completed").is_terminal()
    assert not store.emit("r1", "e1", "status", status="running").is_terminal()
    assert store.emit("r1", "e1", "status", status="rejected").is_terminal()


def test_chat_endpoints_smoke():
    # Importing app.main spins up the FastAPI app; Postgres/Neo4j are unreachable in the test env and
    # every backend call degrades gracefully, so the endpoints still respond.
    from fastapi.testclient import TestClient

    import app.main as m

    client = TestClient(m.app)
    rid = "smoke-run-1"
    m.run_events.emit(rid, "eng1", "plan", stages=["recon"])
    m.run_events.emit(rid, "eng1", "thinking", text="looking at the host")
    m.run_events.emit(rid, "eng1", "status", status="completed")

    # Transcript replays every event in seq order.
    body = client.get(f"/runs/{rid}/transcript").json()
    assert [e["seq"] for e in body["events"]] == [1, 2, 3]
    assert body["events"][0]["kind"] == RunEventKind.plan.value

    # SSE stream drains the buffered events and closes once the terminal status is seen (no hang).
    with client.stream("GET", f"/runs/{rid}/events?after=0") as resp:
        assert resp.status_code == 200
        text = "".join(resp.iter_text())
    assert "data:" in text and "completed" in text

    # Memory + changes endpoints respond even with empty state.
    assert client.get("/engagements/eng1/memory").status_code == 200
    assert client.get("/engagements/eng1/changes?run_id=none").status_code == 200
