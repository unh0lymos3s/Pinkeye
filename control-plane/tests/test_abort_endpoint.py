"""Round 5 — WS A: POST /runs/{run_id}/abort.

Covers the frozen contract in the shared round-5 spec: 404 for an unknown run, 409 once the run has
already reached a terminal status (including the new `aborted` one), the happy path response shape,
and that the route is operator-gated like /runs/{id}/reply. The cooperative-cancellation and
sandbox-kill mechanics themselves are covered in agent-runtime (run_agent honours `run_cancels`;
DockerSandbox.abort kills the in-flight container) — this file only exercises the HTTP boundary.

Run launching is stubbed exactly as in test_profiles_endpoint.py: `_RUN_POOL.submit` never actually
runs `_launch`, so a freshly-created run sits at its initial `queued` status, which is all this file
needs (queued is non-terminal, so it behaves like "in flight" for these purposes).
"""
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.auth import Authenticator
from app.models import RunStatus

OPERATOR_KEY = "op-key"
VIEWER_KEY = "view-key"


@pytest.fixture
def client(monkeypatch):
    # See test_profiles_endpoint.py's fixture docstring: the stub still releases the capacity slot
    # `create_run` acquired, and the rate limiter is opted out so this file's runs don't drain (or get
    # drained by) the shared token bucket other test files depend on.
    monkeypatch.setattr(main._RUN_POOL, "submit",
                        lambda fn, *a, **kw: main._RUN_SLOTS.release(), raising=True)
    monkeypatch.setattr(main.limiter, "allow", lambda tenant_id: True, raising=True)
    monkeypatch.setattr(
        main, "authenticator",
        Authenticator(spec=f"{OPERATOR_KEY}:acme:operator,{VIEWER_KEY}:acme:viewer"),
        raising=True,
    )
    return TestClient(main.app)


def _launch_run(client, key=OPERATOR_KEY) -> str:
    eid = client.post("/engagements", json={"name": "abort-lab"},
                      headers={"X-API-Key": key}).json()["id"]
    res = client.post(f"/engagements/{eid}/runs",
                      json={"target": "10.0.0.5", "mode": "agent", "profile": "scout"},
                      headers={"X-API-Key": key})
    assert res.status_code == 200, res.text
    return res.json()["id"]


def _finish(run_id: str, status: RunStatus) -> None:
    """Drive a run to a terminal status the way the real run thread does — through *both* stores.

    `_set_status` in run_agent writes the in-memory Run object and calls `db.set_run_status`, and
    `_current_run_status` reads the durable row first (mirroring `get_run`), falling back to memory.
    Setting only `main.store.runs[...]` therefore passes solely when Postgres happens to be
    unreachable and the read falls through to memory — which is why this file was green on a machine
    with the stack down and red the moment `deploy/docker-compose.yml` was up. Writing both keeps the
    test honest about which store the endpoint actually consults, in either environment; the durable
    write is best-effort so the file still runs with no database at all.
    """
    main.store.runs[run_id].status = status
    try:
        main.runs.set_status(run_id, status.value)
    except Exception:
        pass  # no database in this environment; the in-memory fallback is what the endpoint will read


def test_abort_unknown_run_404s(client):
    res = client.post("/runs/does-not-exist/abort", headers={"X-API-Key": OPERATOR_KEY})
    assert res.status_code == 404


@pytest.mark.parametrize("status", [
    RunStatus.completed, RunStatus.failed, RunStatus.rejected, RunStatus.aborted,
])
def test_abort_409s_once_the_run_is_terminal(client, status):
    run_id = _launch_run(client)
    _finish(run_id, status)

    res = client.post(f"/runs/{run_id}/abort", headers={"X-API-Key": OPERATOR_KEY})
    assert res.status_code == 409
    assert res.json()["detail"] == "run already finished"


def test_abort_happy_path_returns_aborting(client):
    run_id = _launch_run(client)

    res = client.post(f"/runs/{run_id}/abort", headers={"X-API-Key": OPERATOR_KEY})
    assert res.status_code == 200
    assert res.json() == {"ok": True, "status": "aborting"}

    # The cancellation flag is now set for this run — the piece run_agent's loop polls.
    assert main.run_cancels.is_cancelled(run_id) is True


def test_abort_is_audited_like_reply(client):
    run_id = _launch_run(client)
    main.audit.resolve().events.clear()

    client.post(f"/runs/{run_id}/abort", headers={"X-API-Key": OPERATOR_KEY})

    events = main.audit.resolve().events
    assert any(e.run_id == run_id and e.tool == "abort" and e.allowed is True for e in events)


def test_abort_requires_operator_role(client):
    run_id = _launch_run(client)

    res = client.post(f"/runs/{run_id}/abort", headers={"X-API-Key": VIEWER_KEY})
    assert res.status_code == 403


def test_abort_requires_a_key_at_all(client):
    run_id = _launch_run(client)

    res = client.post(f"/runs/{run_id}/abort")
    assert res.status_code == 401


def test_abort_preflight_passes_for_post(client):
    # CORS `allow_methods` is an enumerated allowlist (see the comment above it in main.py) — POST is
    # already listed for the existing write routes, but pin it for this path too so a future
    # method-list edit that narrows it is caught here rather than in a browser console.
    res = client.options("/runs/some-run/abort", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-api-key",
    })
    assert res.status_code == 200
    assert "POST" in res.headers["access-control-allow-methods"]
