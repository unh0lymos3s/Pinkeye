"""Validation: promote suspected findings to confirmed.

The promotion rule is deterministic and conservative: a finding corroborated across independent runs
(seen more than once) with reasonable confidence is promoted. This raises signal without an LLM
declaring things "confirmed" on its own.

`FindingRepo.promote_corroborated` mirrors this rule as a single set-based UPDATE and imports
`CONFIRM_MIN_CONFIDENCE` from here, so the threshold has one definition.

Exploitation lives in the agent runtime, not here: `runtime/msf.py::MetasploitRpc` is the client and
`runtime/exploit.py::MetasploitExploitTool` carries the gating (`resolve_action`), behind the scope
guard's `allow_exploit` flag.
"""
from __future__ import annotations

CONFIRM_MIN_CONFIDENCE = 0.7


def should_confirm(state: str, confidence: float, times_seen: int) -> bool:
    """A still-open finding, corroborated (>1 run) and confident enough, is safe to confirm."""
    if state == "false_positive":
        return False
    return times_seen >= 2 and confidence >= CONFIRM_MIN_CONFIDENCE
