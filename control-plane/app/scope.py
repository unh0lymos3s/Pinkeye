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


def _target_in_cidrs(target: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(target)
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


def _domain_in_scope(target: str, domains: list[str]) -> bool:
    host = target.lower().rstrip(".")
    for allowed in domains:
        allowed = allowed.lower().lstrip("*.").rstrip(".")
        # Exact match, or a subdomain of an allowed apex (foo.example.com under example.com).
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


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
    the authorized source paths/repos. Signature, time window, and intensity apply to both.
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

    if surface == "knowledge":
        # Knowledge lookups (CVE DB, reputation/threat-intel) don't touch an in-scope target, so
        # there's no allowlist to match; a valid, in-window signed scope is sufficient authorization.
        return Decision(True, "knowledge lookup within authorized engagement")

    if surface == "artifact":
        if _artifact_in_scope(target, scope.allowed_artifacts):
            return Decision(True, "artifact in allowed paths")
        return Decision(False, "artifact not in any allowed path")

    # Peel a URL scheme / port / path off the target so an in-scope host still authorizes when a tool
    # addresses it as `http://host/...` or `host:port`. The host is the authorization boundary.
    host = _target_host(target)
    if not host:
        return Decision(False, "target has no resolvable host")

    if is_ip(host):
        if _target_in_cidrs(host, scope.allowed_cidrs):
            return Decision(True, "ip in allowed cidr")
        return Decision(False, "ip not in any allowed cidr")

    # Anything non-IP is treated as a hostname and checked against the domain allowlist only.
    # We deliberately do not DNS-resolve here: resolution could point outside scope and is not
    # authorization-relevant. Tools that need an IP resolve inside the sandbox and re-check.
    if _domain_in_scope(host, scope.allowed_domains):
        return Decision(True, "host in allowed domain")
    return Decision(False, "host not in any allowed domain")
