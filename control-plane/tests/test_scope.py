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


# --- B1: CIDR targets must be authorized by *containment*, not by peeling the prefix off and
# checking only the bare network address. `_target_host`'s "/" split used to do exactly the latter:
# `authorize(scope, "10.0.0.0/8", ...)` treated "/8" as a path and matched just "10.0.0.0" against
# the allowed CIDRs, so a scope allowing only 10.0.0.0/32 would authorize a scan of the entire /8.
def test_narrower_cidr_inside_allowed_supernet_is_allowed():
    # A /24 fully inside an allowed /16 is a legitimate, narrower scan of the same authorized space.
    scope = make_scope(allowed_cidrs=["10.0.0.0/16"])
    assert authorize(scope, "10.0.5.0/24", Intensity.light).allowed


def test_wide_cidr_against_single_ip_allowlist_is_the_regression_and_must_be_denied():
    # THE REGRESSION: only 10.0.0.0/32 (one address) is authorized. A target of 10.0.0.0/8 covers
    # 16,777,216 addresses; it must be denied outright, never "allowed" via the network address alone.
    scope = make_scope(allowed_cidrs=["10.0.0.0/32"])
    decision = authorize(scope, "10.0.0.0/8", Intensity.light)
    assert not decision.allowed
    assert decision.reason == "network not fully inside any allowed cidr"


def test_slash_32_target_behaves_exactly_like_the_bare_ip():
    scope = make_scope(allowed_cidrs=["10.0.0.0/24"])
    assert authorize(scope, "10.0.0.5/32", Intensity.light).allowed == \
        authorize(scope, "10.0.0.5", Intensity.light).allowed
    out_of_scope = make_scope(allowed_cidrs=["192.168.0.0/24"])
    assert authorize(out_of_scope, "10.0.0.5/32", Intensity.light).allowed == \
        authorize(out_of_scope, "10.0.0.5", Intensity.light).allowed


def test_ipv6_slash_64_inside_allowed_supernet_is_allowed():
    scope = make_scope(allowed_cidrs=["2001:db8::/32"])
    assert authorize(scope, "2001:db8:0:0::/64", Intensity.light).allowed


def test_malformed_cidr_target_is_denied():
    # /99 is not a valid IPv4 prefix length; this must be a hard denial, not a fallback to treating
    # "/99" as a path and matching just the bare (and possibly allowed) address.
    scope = make_scope(allowed_cidrs=["10.0.0.0/24"])
    assert not authorize(scope, "10.0.0.0/99", Intensity.light).allowed


def test_mixed_address_family_cidr_is_denied():
    # An IPv4 target network can never be contained in an IPv6 allowed network, or vice versa.
    scope = make_scope(allowed_cidrs=["2001:db8::/32"])
    assert not authorize(scope, "10.0.0.0/24", Intensity.light).allowed


# --- B3: the scope-guard on/off toggle. An opt-in, signed, audited bypass of the target-allowlist
# match only — never of the signature/time-window/intensity checks, and never of the separate
# `requires_flag` gate execute_tool_step enforces on exploitation/credential tools.
def test_guard_off_still_denies_an_expired_scope():
    now = datetime.now(timezone.utc)
    scope = make_scope(
        scope_guard_enabled=False,
        not_before=now - timedelta(hours=3),
        not_after=now - timedelta(hours=2),
    )
    assert not authorize(scope, "8.8.8.8", Intensity.light).allowed


def test_guard_off_still_denies_a_tampered_scope():
    scope = make_scope(scope_guard_enabled=False)
    scope.allowed_cidrs = ["0.0.0.0/0"]  # mutate after signing -> signature breaks
    assert not authorize(scope, "8.8.8.8", Intensity.light).allowed


def test_guard_off_allows_an_out_of_scope_target_and_says_so():
    scope = make_scope(scope_guard_enabled=False)  # allowed_cidrs is 10.0.0.0/24 by default
    decision = authorize(scope, "8.8.8.8", Intensity.light)  # not in 10.0.0.0/24
    assert decision.allowed
    assert decision.reason == "scope guard disabled for this engagement"


def test_guard_off_does_not_grant_exploit_without_its_own_flag():
    # authorize() itself never checks allow_exploit -- that gate lives in execute_tool_step, keyed off
    # a tool's `requires_flag`. This asserts authorize() stays silent on it either way (guard off does
    # not, for instance, start returning False for some exploit-only reason), and that the scope's
    # allow_exploit is independent of scope_guard_enabled.
    scope = make_scope(scope_guard_enabled=False, allow_exploit=False)
    assert authorize(scope, "8.8.8.8", Intensity.light).allowed  # guard-off target bypass still works
    assert scope.allow_exploit is False  # disabling the guard never flips the separate flag


def test_flipping_guard_off_reasigns_and_invalidates_the_old_signature():
    scope = make_scope()  # guard on, signed
    old_signature = scope.signature
    scope.scope_guard_enabled = False
    # The old (guard-on) signature must no longer validate now that canonical() has changed.
    assert not authorize(scope, "10.0.0.5", Intensity.light).allowed
    scope.signature = sign_scope(scope)  # re-sign, as the PATCH endpoint does
    assert scope.signature != old_signature
    assert authorize(scope, "8.8.8.8", Intensity.light).allowed


def test_default_guard_on_signature_is_unchanged_by_the_new_field():
    # Regression: adding scope_guard_enabled must not perturb canonical()/signatures for the default
    # (guard-on) case -- every engagement signed before this field existed must keep validating.
    now = datetime.now(timezone.utc)
    fields = dict(
        allowed_cidrs=["10.0.0.0/24"],
        allowed_domains=["example.com"],
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
        max_intensity=Intensity.normal,
    )
    explicit_default = Scope(**fields, scope_guard_enabled=True)
    implicit_default = Scope(**fields)
    assert explicit_default.canonical() == implicit_default.canonical()
    # A signature computed without ever knowing about the field still validates the same scope.
    sig = sign_scope(implicit_default)
    implicit_default.signature = sig
    assert authorize(implicit_default, "10.0.0.5", Intensity.light).allowed
