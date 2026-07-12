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

    if is_ip(target):
        if _target_in_cidrs(target, scope.allowed_cidrs):
            return Decision(True, "ip in allowed cidr")
        return Decision(False, "ip not in any allowed cidr")

    # Anything non-IP is treated as a hostname and checked against the domain allowlist only.
    # We deliberately do not DNS-resolve here: resolution could point outside scope and is not
    # authorization-relevant. Tools that need an IP resolve inside the sandbox and re-check.
    if _domain_in_scope(target, scope.allowed_domains):
        return Decision(True, "host in allowed domain")
    return Decision(False, "host not in any allowed domain")
