"""Validation: promote suspected findings to confirmed, and a strictly-gated exploit client.

Promotion rule is deterministic and conservative: a finding corroborated across independent runs
(seen more than once) with reasonable confidence is promoted. This raises signal without an LLM
declaring things "confirmed" on its own.

MetasploitClient exists for optional, opt-in validation. It is check-only by default and refuses to
run an actual exploit unless explicitly enabled — offensive actions must be a deliberate choice, not
a default the agent can stumble into.
"""
from __future__ import annotations

CONFIRM_MIN_CONFIDENCE = 0.7


def should_confirm(state: str, confidence: float, times_seen: int) -> bool:
    """A still-open finding, corroborated (>1 run) and confident enough, is safe to confirm."""
    if state == "false_positive":
        return False
    return times_seen >= 2 and confidence >= CONFIRM_MIN_CONFIDENCE


class ExploitNotAllowed(RuntimeError):
    pass


class MetasploitClient:
    def __init__(self, enabled: bool = False, allow_exploit: bool = False):
        # Both flags default off: the client does nothing unless an operator turns it on.
        self._enabled = enabled
        self._allow_exploit = allow_exploit

    def check(self, module: str, target: str) -> dict:
        """Run a module's non-destructive `check` only. Safe to call during validation."""
        if not self._enabled:
            return {"skipped": "metasploit disabled"}
        # Real integration would talk to msfrpcd here; kept as the gated seam.
        return {"module": module, "target": target, "action": "check"}

    def exploit(self, module: str, target: str) -> dict:
        """Run an actual exploit. Refused unless explicitly allowed — never a silent default."""
        if not (self._enabled and self._allow_exploit):
            raise ExploitNotAllowed("exploitation requires enabled=True and allow_exploit=True")
        return {"module": module, "target": target, "action": "exploit"}
