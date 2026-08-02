"""The scope guard: the single un-bypassable check that authorizes every tool invocation.

Design rules:
  - Deny by default. Any error, ambiguity, or unverifiable input returns a denial.
  - This is code, never a prompt. The LLM cannot reason its way past it.
  - It runs before a tool touches the network, and every decision is written to the audit log.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import settings
from .matching import host_in_domains, ip_in_cidrs, network_in_cidrs
from .models import Intensity, Scope, is_ip

# Intensity ordering, used to enforce the engagement's ceiling.
_INTENSITY_RANK = {
    Intensity.passive: 0,
    Intensity.light: 1,
    Intensity.normal: 2,
    Intensity.aggressive: 3,
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def sign_scope(scope: Scope, key: str | None = None) -> str:
    """Produce the HMAC signature for a scope. Called when an engagement is created."""
    secret = (key or settings.scope_signing_key).encode()
    return hmac.new(secret, scope.canonical().encode(), hashlib.sha256).hexdigest()


def _signature_valid(scope: Scope) -> bool:
    if not scope.signature:
        return False
    expected = sign_scope(scope)
    # Constant-time compare so a bad signature can't be brute-forced by timing.
    return hmac.compare_digest(expected, scope.signature)


def _target_host(target: str) -> str:
    """Extract the bare host from a network target for the scope decision.

    Tools legitimately pass a target with a URL scheme (`http://10.0.0.5/app`, for nuclei/nikto/zap)
    or a port (`10.0.0.5:443`, for nmap port scans / tls_cert). The authorization boundary is the
    *host*, not the port or path, so we peel those off before matching CIDRs/domains. Extraction is
    conservative and follows standard URL-authority rules (userinfo before `@`, host after); anything
    ambiguous returns "" and is denied by the caller. It never DNS-resolves.
    """
    t = target.strip()
    if "://" in t:              # strip a scheme (http://, https://, anything://)
        t = t.split("://", 1)[1]
    for sep in ("/", "?", "#"):  # authority ends at the first path/query/fragment separator
        i = t.find(sep)
        if i != -1:
            t = t[:i]
    if "@" in t:                # drop userinfo (user:pass@host) -> keep the real host
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):       # bracketed IPv6, optionally with a port: [::1]:443
        end = t.find("]")
        return t[1:end] if end != -1 else ""
    if t.count(":") > 1:        # bare IPv6 (can't carry a port without brackets) -> leave intact
        return t
    if ":" in t:                # host:port -> strip a numeric port only
        host, _, port = t.rpartition(":")
        return host if port.isdigit() else t
    return t


def _target_network(target: str) -> tuple[bool, "ipaddress.IPv4Network | ipaddress.IPv6Network | None"]:
    """Detect whether `target` denotes a whole network ("address/prefixlen"), as opposed to a bare
    host possibly followed by a path.

    Returns `(is_network_shaped, network_or_None)`. Strips a URL scheme and userinfo the same way
    `_target_host` does, but — unlike `_target_host` — does NOT treat the first "/" it finds as a
    path separator, because a CIDR is legitimately written as `address/prefixlen` and that "/" *is*
    the prefix, not a path. Splitting there is the historical bug B1 fixes: it silently truncated the
    target down to the bare network address (`"10.0.0.0/8"` -> `"10.0.0.0"`), which then got checked
    -- and could be authorized -- as a single host, while the tool was still handed the full,
    unauthorized range.

    `is_network_shaped` is True whenever the text after the first "/" is purely digits, i.e. it looks
    like an attempted prefix length (not a path or query, which would contain other characters). The
    caller must treat "network-shaped but failed to parse" (`is_network_shaped=True`,
    `network=None` — e.g. an out-of-range prefix like "/99") as a malformed network and deny outright,
    rather than falling back to host matching, which would just repeat the same truncation bug on a
    different malformed input.
    """
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if "/" not in t:
        return False, None
    _, _, tail = t.partition("/")
    if not tail.isdigit():
        return False, None
    try:
        return True, ipaddress.ip_network(t, strict=False)
    except ValueError:
        return True, None


def _artifact_in_scope(target: str, artifacts: list[str]) -> bool:
    # Static-analysis targets are paths/repo URLs; allow if under an authorized prefix.
    return any(target == a or target.startswith(a.rstrip("/") + "/") or target == a.rstrip("/")
               for a in artifacts)


def authorize(
    scope: Scope,
    target: str,
    intensity: Intensity,
    now: datetime | None = None,
    surface: str = "network",
) -> Decision:
    """Return whether `target` at `intensity` is permitted by `scope`. Deny by default.

    `surface` selects the allowlist: network tools check CIDRs/domains; artifact (SAST) tools check
    the authorized source paths/repos. Signature, time window, and intensity apply to both — and
    still do even when the scope guard's target match is disabled below (B3): that flag only ever
    widens *which target* is authorized, never *whether an unsigned/expired/over-intensity request*
    is. It also never touches `execute_tool_step`'s separate `requires_flag` check — exploitation and
    credential-attack tools stay gated behind their own signed scope flags no matter what this
    returns; see orchestrator.py.
    """
    now = now or datetime.now(timezone.utc)

    if not _signature_valid(scope):
        return Decision(False, "scope signature missing or invalid")

    if now < scope.not_before or now > scope.not_after:
        return Decision(False, "outside authorized time window")

    if _INTENSITY_RANK[intensity] > _INTENSITY_RANK[scope.max_intensity]:
        return Decision(False, f"intensity {intensity.value} exceeds ceiling {scope.max_intensity.value}")

    target = target.strip()
    if not target:
        return Decision(False, "empty target")

    if not scope.scope_guard_enabled:
        # B3: an explicit, signed, audited operator bypass (PATCH /engagements/{id}/scope-guard,
        # admin-only to turn off) — not a silent kill switch. Everything above this line (signature,
        # time window, intensity ceiling) still applies unconditionally; this only skips the
        # target-allowlist match that follows, because with the guard off every target is, by design,
        # authorized for this engagement. The caller (orchestrator.execute_tool_step) audits this
        # decision's reason verbatim, so a replay can never mistake this for an ordinary allow.
        return Decision(True, "scope guard disabled for this engagement")

    if surface == "knowledge":
        # Knowledge lookups (CVE DB, reputation/threat-intel) don't touch an in-scope target, so
        # there's no allowlist to match; a valid, in-window signed scope is sufficient authorization.
        return Decision(True, "knowledge lookup within authorized engagement")

    if surface == "artifact":
        if _artifact_in_scope(target, scope.allowed_artifacts):
            return Decision(True, "artifact in allowed paths")
        return Decision(False, "artifact not in any allowed path")

    # B1: a target with an explicit "/prefixlen" denotes a whole network, not a single host — take
    # that branch *before* the host-oriented parsing below, which would otherwise treat the "/" as a
    # path separator and truncate "10.0.0.0/8" down to the bare address "10.0.0.0" (see
    # `_target_network`'s docstring for the bug that produced). A network is only authorized when it
    # is *entirely* contained in an allowed CIDR — checking only its network address, as the old code
    # did, authorized the address while leaving the whole range to reach the tool unchecked. A `/32`
    # (or IPv6 `/128`) target reduces to exactly the bare-IP check below, by construction.
    is_network, network = _target_network(target)
    if is_network:
        if network is not None and network_in_cidrs(str(network), scope.allowed_cidrs):
            return Decision(True, "network inside allowed cidr")
        return Decision(False, "network not fully inside any allowed cidr")

    # Peel a URL scheme / port / path off the target so an in-scope host still authorizes when a tool
    # addresses it as `http://host/...` or `host:port`. The host is the authorization boundary.
    host = _target_host(target)
    if not host:
        return Decision(False, "target has no resolvable host")

    if is_ip(host):
        if ip_in_cidrs(host, scope.allowed_cidrs):
            return Decision(True, "ip in allowed cidr")
        return Decision(False, "ip not in any allowed cidr")

    # Anything non-IP is treated as a hostname and checked against the domain allowlist only.
    # We deliberately do not DNS-resolve here: resolution could point outside scope and is not
    # authorization-relevant. Tools that need an IP resolve inside the sandbox and re-check.
    if host_in_domains(host, scope.allowed_domains):
        return Decision(True, "host in allowed domain")
    return Decision(False, "host not in any allowed domain")
