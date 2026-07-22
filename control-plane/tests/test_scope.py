"""Scope guard is the harness's most important safety property, so it gets the most tests.

The core assertion: an out-of-scope target is hard-rejected, and only a correctly-signed,
in-window, in-allowlist, within-intensity request is allowed.
"""
from datetime import datetime, timedelta, timezone

from app.models import Intensity, Scope
from app.scope import authorize, sign_scope


def make_scope(**overrides) -> Scope:
    now = datetime.now(timezone.utc)
    fields = dict(
        allowed_cidrs=["10.0.0.0/24"],
        allowed_domains=["example.com"],
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
        max_intensity=Intensity.normal,
    )
    fields.update(overrides)
    scope = Scope(**fields)
    scope.signature = sign_scope(scope)
    return scope


def test_in_scope_ip_allowed():
    assert authorize(make_scope(), "10.0.0.5", Intensity.light).allowed


def test_out_of_scope_ip_rejected():
    decision = authorize(make_scope(), "192.168.1.1", Intensity.light)
    assert not decision.allowed


def test_subdomain_of_allowed_domain_allowed():
    assert authorize(make_scope(), "api.example.com", Intensity.light).allowed


def test_unrelated_domain_rejected():
    assert not authorize(make_scope(), "evil.com", Intensity.light).allowed
    # A domain that merely ends with the allowed string but isn't a subdomain must be rejected.
    assert not authorize(make_scope(), "notexample.com", Intensity.light).allowed


def test_tampered_scope_rejected():
    scope = make_scope()
    scope.allowed_cidrs = ["0.0.0.0/0"]  # widen the scope after signing -> signature breaks
    assert not authorize(scope, "1.2.3.4", Intensity.light).allowed


def test_unsigned_scope_rejected():
    scope = make_scope()
    scope.signature = None
    assert not authorize(scope, "10.0.0.5", Intensity.light).allowed


def test_outside_time_window_rejected():
    now = datetime.now(timezone.utc)
    scope = make_scope(not_before=now - timedelta(hours=3), not_after=now - timedelta(hours=2))
    assert not authorize(scope, "10.0.0.5", Intensity.light).allowed


def test_intensity_ceiling_enforced():
    scope = make_scope(max_intensity=Intensity.light)
    assert authorize(scope, "10.0.0.5", Intensity.light).allowed
    assert not authorize(scope, "10.0.0.5", Intensity.aggressive).allowed


# --- Target host extraction: an in-scope host stays in scope when addressed with a port/scheme/path.
# These are the forms real tools produce (nmap `ip:port`, nuclei/nikto/zap `http://ip/...`).
def test_in_scope_ip_with_port_allowed():
    assert authorize(make_scope(), "10.0.0.5:22", Intensity.light).allowed


def test_in_scope_ip_with_url_scheme_allowed():
    assert authorize(make_scope(), "http://10.0.0.5", Intensity.light).allowed


def test_in_scope_ip_with_scheme_port_and_path_allowed():
    assert authorize(make_scope(), "https://10.0.0.5:8443/admin?q=1", Intensity.light).allowed


def test_in_scope_domain_with_scheme_and_port_allowed():
    assert authorize(make_scope(), "https://api.example.com:443/login", Intensity.light).allowed


def test_in_scope_ipv6_with_brackets_and_port_allowed():
    scope = make_scope(allowed_cidrs=["2001:db8::/32"])
    assert authorize(scope, "[2001:db8::1]:443", Intensity.light).allowed


# --- SAFETY: extraction must not let an out-of-scope host slip through.
def test_out_of_scope_ip_with_port_still_rejected():
    assert not authorize(make_scope(), "192.168.1.1:80", Intensity.light).allowed


def test_out_of_scope_host_in_url_still_rejected():
    assert not authorize(make_scope(), "http://evil.com:8080/x", Intensity.light).allowed


def test_userinfo_cannot_spoof_an_in_scope_host():
    # The real host is after the '@'. An in-scope host placed in the userinfo must NOT authorize.
    assert not authorize(make_scope(), "http://10.0.0.5@evil.com/", Intensity.light).allowed
    # And the legitimate inverse (in-scope host as the real host) is allowed.
    assert authorize(make_scope(), "http://evil.com@10.0.0.5/", Intensity.light).allowed


def test_empty_or_hostless_target_rejected():
    assert not authorize(make_scope(), "http:///justpath", Intensity.light).allowed
