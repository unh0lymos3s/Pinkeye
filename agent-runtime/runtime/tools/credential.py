"""Gated, rate-limited credential attack (hydra) tool.

Requires `allow_credential_attacks` in the signed scope. Two hard safety caps are baked into the
command, not left to the caller:
  - a low task/thread count and an inter-attempt wait, so we don't lock accounts out or DoS the service
  - a bounded number of password guesses (a small wordlist), so this is spray/weak-credential testing,
    not unbounded brute force
The scope guard confirms the target is authorized; the tool confirms the attack is authorized.
"""
from __future__ import annotations

from app.models import Intensity

from ..normalize.hydra import parse_hydra_output
from .base import ToolOutput

# Threads and wait per intensity — capped so even "aggressive" stays lockout-safe.
_THREADS = {Intensity.passive: "1", Intensity.light: "2", Intensity.normal: "4", Intensity.aggressive: "4"}
_WAIT = {Intensity.passive: "5", Intensity.light: "3", Intensity.normal: "2", Intensity.aggressive: "1"}
_MAX_THREADS = 4  # never exceed, regardless of intensity


class CredentialAttackTool:
    name = "credential_attack"
    description = (
        "Test for weak/guessable credentials on a service with hydra (spray, not brute force). "
        "Target is host[:port]. Requires allow_credential_attacks in scope. Provide service via context."
    )
    image = "vanhauser/hydra:latest"
    surface = "network"
    wants_context = True
    requires_flag = "allow_credential_attacks"

    def build_command(self, target: str, intensity: Intensity, context: dict | None = None) -> list[str]:
        context = context or {}
        service = context.get("service", "ssh")
        host, _, port = target.partition(":")
        threads = min(int(_THREADS[intensity]), _MAX_THREADS)
        # Small, bundled lists keep this to spraying common weak creds. -W throttles per-attempt.
        userlist = context.get("userlist", "/usr/share/wordlists/users-small.txt")
        passlist = context.get("passlist", "/usr/share/wordlists/pass-small.txt")
        cmd = ["-L", userlist, "-P", passlist, "-t", str(threads), "-W", _WAIT[intensity], "-f"]
        if port:
            cmd += ["-s", port]
        cmd += [host, service]
        return cmd

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_hydra_output(raw, engagement_id=engagement_id, run_id=run_id, target=target)


def credential_tools() -> list:
    return [CredentialAttackTool()]
