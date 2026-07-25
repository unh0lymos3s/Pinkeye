"""Target-matching primitives shared by the scope guard and the egress policy.

These two consumers answer the same question at two different layers: `app/scope.py` decides whether
a tool may *address* a target, and `runtime/egress.py` decides which destinations that tool's sandbox
may *reach*. They were separate implementations that had already drifted (trailing-dot normalization),
and a divergence between them is a silent hole in defense-in-depth: the egress backstop would refuse
a destination the guard authorized, or — worse in the other direction — permit one it did not.

One implementation, imported by both. The semantics here are exactly `scope.py`'s, because that is
the un-bypassable authorization boundary and it is the one that must not shift.

Deny by default: anything unparseable (a bad address, a malformed CIDR) matches nothing rather than
widening access.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable


def ip_in_cidrs(ip: str, cidrs: Iterable[str]) -> bool:
    """Whether `ip` falls inside any of `cidrs`. A malformed entry is skipped, never widening."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            # A malformed CIDR in the scope must never widen access; skip it.
            continue
    return False


def normalize_domain(domain: str) -> str:
    """Canonical form of an allowlist entry: lowercase, wildcard prefix and trailing dot removed.

    Note `lstrip("*.")` strips any leading run of `*` and `.` characters, not just the literal
    `"*."` prefix — so an entry of `*.com` normalizes to `com` and then matches every `.com` host.
    That is pre-existing behaviour, preserved deliberately here; validating allowlist entries at
    engagement-creation time is the place to tighten it.

    Idempotent, so it is safe to apply to entries a caller has already normalized.
    """
    return domain.lower().lstrip("*.").rstrip(".")


def normalize_host(host: str) -> str:
    """Canonical form of a host being tested: lowercase, trailing root dot removed."""
    return host.lower().rstrip(".")


def host_in_domains(host: str, domains: Iterable[str]) -> bool:
    """Whether `host` is an allowed apex or a subdomain of one.

    The `"." + allowed` prefix on the suffix test is what keeps `notexample.com` out of scope for an
    allowlist of `example.com` — a plain `endswith` would admit it.
    """
    host = normalize_host(host)
    for allowed in domains:
        allowed = normalize_domain(allowed)
        if host == allowed or host.endswith("." + allowed):
            return True
    return False
