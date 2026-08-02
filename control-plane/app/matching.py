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


def network_in_cidrs(target: str, cidrs: Iterable[str]) -> bool:
    """Whether the *whole network* `target` denotes (e.g. "10.0.0.0/8", or a bare "/32") is entirely
    contained within at least one of `cidrs`.

    This answers a different question than `ip_in_cidrs`, deliberately: that function asks "is this
    one address inside an allowed network", which is the wrong test when `target` is itself a range.
    Extracting just the network address from a CIDR target (a naive split at the first "/") and
    running that through `ip_in_cidrs` was exactly the historical bug here — a scope allowing only
    `10.0.0.0/32` would authorize the address `10.0.0.0`, and a target of `10.0.0.0/8` would then be
    "allowed" even though the other 16,777,214 addresses in that range were never authorized. The only
    sound check is containment of the *whole* target network inside an allowed network: `target` must
    be a `subnet_of` (or equal to) some entry in `cidrs`, in the same address family.

    A `/32` (or IPv6 `/128`) target is a network of exactly one address, so this reduces to
    `ip_in_cidrs`'s answer for that address — the bare-IP case is not special-cased separately.

    Deny by default, mirroring `ip_in_cidrs`: a malformed `target` or a malformed/mismatched-family
    entry in `cidrs` is treated as non-containing rather than raising or widening access.
    """
    try:
        target_net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            allowed_net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            # A malformed CIDR in the scope must never widen access; skip it.
            continue
        if target_net.version != allowed_net.version:
            continue  # comparing across address families is meaningless; never match
        if target_net.subnet_of(allowed_net):
            return True
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
