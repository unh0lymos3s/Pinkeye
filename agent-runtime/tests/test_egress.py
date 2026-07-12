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
