"""Phase 7 tests: API-key RBAC, per-tenant rate limiting, and tenant-scoped queries."""
from app.auth import Authenticator, has_role, parse_api_keys
from app.query import FindingFilters, build_findings_query
from app.ratelimit import RateLimiter


def test_api_key_parsing_and_roles():
    keys = parse_api_keys("k1:acme:admin, k2:beta:viewer, bad-entry, k3:x:notarole")
    assert keys["k1"].tenant_id == "acme" and keys["k1"].role == "admin"
    assert keys["k2"].role == "viewer"
    assert "bad-entry" not in keys and "k3" not in keys  # malformed/invalid dropped


def test_role_hierarchy():
    admin = parse_api_keys("k:t:admin")["k"]
    viewer = parse_api_keys("k:t:viewer")["k"]
    assert has_role(admin, "operator") and has_role(admin, "viewer")
    assert has_role(viewer, "viewer")
    assert not has_role(viewer, "operator")


def test_open_dev_mode_when_no_keys():
    auth = Authenticator(spec="")
    assert auth.open_dev_mode
    p = auth.principal_for(None)  # no key needed in dev mode
    assert p.tenant_id == "default" and p.role == "admin"


def test_auth_rejects_unknown_key_when_configured():
    auth = Authenticator(spec="good:acme:operator")
    assert auth.principal_for("good").tenant_id == "acme"
    assert auth.principal_for("bogus") is None
    assert auth.principal_for(None) is None


def test_rate_limiter_blocks_after_burst_then_refills():
    t = [0.0]
    limiter = RateLimiter(rate_per_min=60, burst=2, _clock=lambda: t[0])
    assert limiter.allow("acme")   # token 1
    assert limiter.allow("acme")   # token 2
    assert not limiter.allow("acme")  # burst exhausted
    t[0] = 1.5  # 1.5s at 60/min = 1.5 tokens refilled
    assert limiter.allow("acme")
    # A different tenant has its own bucket.
    assert limiter.allow("beta")


def test_findings_query_scopes_to_tenant():
    sql, params = build_findings_query("e1", FindingFilters(severity="high"), tenant_id="acme")
    assert "tenant_id = %s" in sql
    assert params[:3] == ["e1", "acme", "high"]
