"""Phase 6: per-job egress policy derived from scope."""
from datetime import datetime, timedelta, timezone

from app.models import Scope
from runtime.egress import EgressPolicy


def _scope():
    now = datetime.now(timezone.utc)
    return Scope(
        allowed_cidrs=["10.0.0.0/24"], allowed_domains=["example.com"],
        not_before=now, not_after=now + timedelta(hours=1),
    )


def test_egress_allows_only_scoped_destinations():
    policy = EgressPolicy.from_scope(_scope())
    assert policy.allows_ip("10.0.0.7")
    assert not policy.allows_ip("8.8.8.8")
    assert policy.allows_host("api.example.com")
    assert not policy.allows_host("evil.com")


# --- B3: with the engagement's scope guard disabled, the egress backstop must not re-deny what the
# guard already authorized -- it goes unrestricted in lockstep, rather than silently refusing traffic
# the operator explicitly opted to allow.
def test_egress_is_unrestricted_when_scope_guard_disabled():
    scope = _scope()
    scope.scope_guard_enabled = False
    policy = EgressPolicy.from_scope(scope)
    assert policy.unrestricted
    assert policy.allows_ip("8.8.8.8")  # not in allowed_cidrs, but the guard is off
    assert policy.allows_host("evil.com")  # not in allowed_domains, but the guard is off


def test_egress_stays_restricted_when_scope_guard_enabled():
    policy = EgressPolicy.from_scope(_scope())  # default scope_guard_enabled=True
    assert not policy.unrestricted
    assert not policy.allows_ip("8.8.8.8")
    assert not policy.allows_host("evil.com")
