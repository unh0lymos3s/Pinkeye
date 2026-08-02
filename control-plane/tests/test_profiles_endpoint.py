"""The persona roster at the API boundary: what `/profiles` publishes and what `create_run` accepts.

These are the two contracts the web UI is written against. The launcher renders whatever `/profiles`
returns (glyph, label, tool list), and every run it launches names a persona — so a drift in either
shape is a broken launcher, not a caught exception.

Run launching is stubbed out here: the validation this file covers all happens *before* the executor
is handed the job, and a real submit would try to build a Docker sandbox on a machine that may not
have one. Nothing about the checks under test depends on the run actually starting.
"""
import pytest
from fastapi.testclient import TestClient

import app.main as main


@pytest.fixture
def client(monkeypatch):
    # Accept the run, but never execute it — see the module docstring. The stub still releases the
    # capacity slot the endpoint acquired, which is what the real `_launch` does in its `finally`:
    # without it these tests would leak a slot per accepted run and start 503ing partway through
    # the file, turning a shared-state bug into a confusing failure in whichever test ran ninth.
    monkeypatch.setattr(main._RUN_POOL, "submit",
                        lambda fn, *a, **kw: main._RUN_SLOTS.release(), raising=True)
    # The rate limiter is a process-wide token bucket keyed by tenant, and this file launches more
    # runs than the default burst allows. Left alone it would drain the shared bucket and 429 the
    # *next* test file to POST anything — so opt this file out rather than have it charge its
    # fixtures to a budget other tests depend on. Rate limiting has its own coverage elsewhere.
    monkeypatch.setattr(main.limiter, "allow", lambda tenant_id: True, raising=True)
    return TestClient(main.app)


def _engagement(client) -> str:
    return client.post("/engagements", json={"name": "persona-lab"}).json()["id"]


def test_profiles_publishes_the_fields_the_launcher_renders():
    body = TestClient(main.app).get("/profiles").json()
    profiles = body["profiles"]
    by_id = {p["id"]: p for p in profiles}

    # The orchestrator leads and the generalist trails, so the picker's first entry is the default.
    assert profiles[0]["id"] == "overseer" and profiles[-1]["id"] == "jack"
    for required in ("id", "label", "glyph", "accent", "tagline", "stage", "gated_flag",
                     "orchestrator", "generalist", "tools", "aliases"):
        assert all(required in p for p in profiles), required

    # A persona's `tools` is its exact toolkit — the tools dropdown shows this list and nothing else.
    assert by_id["scout"]["tools"] == ["nmap"]
    assert set(by_id["viper"]["tools"]) == {"nuclei", "ffuf", "nikto", "zap"}
    assert by_id["overseer"]["tools"] == [] and by_id["overseer"]["orchestrator"] is True

    # Gating is reflected, never granted: the flag names the scope attribute the guard enforces.
    assert by_id["reaper"]["gated_flag"] == "allow_exploit"
    assert by_id["ghost"]["gated_flag"] == "allow_credential_attacks"
    assert by_id["scout"]["gated_flag"] is None


def test_tools_endpoint_carries_the_stage_used_for_grouping():
    tools = TestClient(main.app).get("/tools").json()
    stages = {t["name"]: t["stage"] for t in tools}
    assert stages["nmap"] == "recon" and stages["semgrep"] == "static scan"


@pytest.mark.parametrize("method,path", [
    ("GET", "/profiles"),
    ("POST", "/engagements"),
    ("PATCH", "/engagements/any-id/scope-guard"),
])
def test_browser_preflight_passes_for_every_verb_the_ui_uses(method, path):
    """CORS `allow_methods` is an enumerated allowlist, so a route added with a *new* verb is
    reachable by curl and by the tests while being unusable from the browser: the preflight 400s and
    `fetch` reports it as a bare `TypeError: Failed to fetch` that names neither CORS nor the method.
    That is precisely how the scope-guard toggle shipped broken. Pin the preflight per verb so the
    next route with an unlisted method fails here instead of in someone's console."""
    res = TestClient(main.app).options(path, headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "content-type",
    })
    assert res.status_code == 200, f"{method} {path} preflight rejected: {res.status_code}"
    assert method in res.headers["access-control-allow-methods"]


def test_unknown_profile_is_rejected(client):
    eid = _engagement(client)
    res = client.post(f"/engagements/{eid}/runs",
                      json={"target": "10.0.0.5", "mode": "agent", "profile": "gandalf"})
    assert res.status_code == 400
    assert "gandalf" in res.text


@pytest.mark.parametrize("alias,persona", [
    ("full", "overseer"), ("flat", "jack"), ("recon", "scout"),
    ("dast", "viper"), ("exploit", "reaper"), ("credentials", "ghost"),
])
def test_legacy_profile_names_still_launch(client, alias, persona):
    # The pre-persona UI (and anyone's saved scripts) named profiles by stage. Those keep working as
    # aliases, so renaming the roster to personalities is not a breaking API change.
    eid = _engagement(client)
    res = client.post(f"/engagements/{eid}/runs",
                      json={"target": "10.0.0.5", "mode": "agent", "profile": alias})
    assert res.status_code == 200, res.text


def test_enabled_tools_cannot_escape_the_personas_toolkit(client):
    # The tool library narrows what a persona may use; it must never widen it. Scout owns nmap only,
    # so asking it for the exploit tool is refused at the boundary rather than quietly ignored.
    eid = _engagement(client)
    res = client.post(f"/engagements/{eid}/runs", json={
        "target": "10.0.0.5", "mode": "agent", "profile": "scout",
        "enabled_tools": ["nmap", "exploit"],
    })
    assert res.status_code == 400
    assert "exploit" in res.text and "nmap" not in res.json()["detail"]


def test_enabled_tools_within_the_toolkit_are_accepted(client):
    eid = _engagement(client)
    res = client.post(f"/engagements/{eid}/runs", json={
        "target": "10.0.0.5", "mode": "agent", "profile": "viper",
        "enabled_tools": ["nuclei", "zap"],
    })
    assert res.status_code == 200, res.text


def test_orchestrator_may_select_any_tool_for_its_specialists(client):
    # The overseer owns no tools itself — its selection is the pool its specialists draw from, so the
    # subset rule that applies to a specialist persona must not apply here.
    eid = _engagement(client)
    res = client.post(f"/engagements/{eid}/runs", json={
        "target": "10.0.0.5", "mode": "agent", "profile": "overseer",
        "enabled_tools": ["nmap", "nuclei", "semgrep"],
    })
    assert res.status_code == 200, res.text
