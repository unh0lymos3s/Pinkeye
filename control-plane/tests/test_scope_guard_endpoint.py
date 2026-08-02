"""B3 endpoint tests: the operator-facing scope-guard on/off toggle.

Covers the two roles it must be exercised under (operator vs admin), that disabling re-signs the
scope (so `scope.authorize()` actually reflects the flip), and that the change is audited either way.
Uses a configured `Authenticator` (rather than open dev mode) so operator/admin actually differ.
"""
from fastapi.testclient import TestClient

import app.main as main
from app.auth import Authenticator

OPERATOR_KEY = "op-key"
ADMIN_KEY = "admin-key"


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(
        main, "authenticator",
        Authenticator(spec=f"{OPERATOR_KEY}:acme:operator,{ADMIN_KEY}:acme:admin"),
        raising=True,
    )
    return TestClient(main.app)


def _create(client, key=OPERATOR_KEY, **overrides):
    body = {"name": "guard-lab", **overrides}
    return client.post("/engagements", json=body, headers={"X-API-Key": key})


def test_create_engagement_defaults_scope_guard_enabled():
    client = TestClient(main.app)  # open dev mode is fine for the default-value check
    eng = client.post("/engagements", json={"name": "default-lab"}).json()
    assert eng["scope"]["scope_guard_enabled"] is True


def test_get_and_list_engagements_expose_scope_guard_enabled(monkeypatch):
    client = _client(monkeypatch)
    eid = _create(client).json()["id"]

    got = client.get(f"/engagements/{eid}", headers={"X-API-Key": OPERATOR_KEY}).json()
    assert got["scope"]["scope_guard_enabled"] is True

    listed = client.get("/engagements", headers={"X-API-Key": OPERATOR_KEY}).json()
    assert any(e["id"] == eid and e["scope"]["scope_guard_enabled"] is True for e in listed)


def test_operator_cannot_create_engagement_with_guard_disabled(monkeypatch):
    client = _client(monkeypatch)
    res = _create(client, key=OPERATOR_KEY, scope_guard_enabled=False)
    assert res.status_code == 403


def test_admin_can_create_engagement_with_guard_disabled(monkeypatch):
    client = _client(monkeypatch)
    res = _create(client, key=ADMIN_KEY, scope_guard_enabled=False)
    assert res.status_code == 200
    assert res.json()["scope"]["scope_guard_enabled"] is False


def test_operator_cannot_disable_scope_guard(monkeypatch):
    client = _client(monkeypatch)
    eid = _create(client).json()["id"]

    res = client.patch(
        f"/engagements/{eid}/scope-guard", json={"enabled": False},
        headers={"X-API-Key": OPERATOR_KEY},
    )
    assert res.status_code == 403
    # Nothing changed: the engagement is still guard-on.
    still = client.get(f"/engagements/{eid}", headers={"X-API-Key": OPERATOR_KEY}).json()
    assert still["scope"]["scope_guard_enabled"] is True


def test_admin_can_disable_and_operator_can_re_enable(monkeypatch):
    client = _client(monkeypatch)
    eid = _create(client).json()["id"]
    before = main._load_engagement(eid).scope.signature

    res = client.patch(
        f"/engagements/{eid}/scope-guard", json={"enabled": False},
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["scope"]["scope_guard_enabled"] is False

    disabled = main._load_engagement(eid)
    assert disabled.scope.scope_guard_enabled is False
    # Disabling changed the signature (guard=0 enters canonical() only when off).
    assert disabled.scope.signature != before
    # The stale, guard-on signature must no longer validate this (now guard-off) scope.
    from app.scope import authorize
    from app.models import Intensity
    tampered = disabled.scope.model_copy(update={"signature": before})
    assert not authorize(tampered, "8.8.8.8", Intensity.light).allowed

    # Re-enabling only needs operator.
    res2 = client.patch(
        f"/engagements/{eid}/scope-guard", json={"enabled": True},
        headers={"X-API-Key": OPERATOR_KEY},
    )
    assert res2.status_code == 200
    reenabled = main._load_engagement(eid)
    assert reenabled.scope.scope_guard_enabled is True
    # Re-enabling restores the original guard-on signature exactly (canonical() is identical again).
    assert reenabled.scope.signature == before


def test_scope_guard_flip_is_audited(monkeypatch):
    client = _client(monkeypatch)
    eid = _create(client).json()["id"]
    main.audit.resolve().events.clear()

    client.patch(f"/engagements/{eid}/scope-guard", json={"enabled": False},
                headers={"X-API-Key": ADMIN_KEY})

    events = main.audit.resolve().events
    assert any(
        e.engagement_id == eid and e.tool == "scope-guard" and "DISABLED" in e.detail
        for e in events
    )


def test_scope_guard_endpoint_404s_for_unknown_engagement(monkeypatch):
    client = _client(monkeypatch)
    res = client.patch(
        "/engagements/does-not-exist/scope-guard", json={"enabled": False},
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert res.status_code == 404
