"""Shared environment-variable parsers for the control plane's tuning knobs.

Identical-in-behaviour copies of these were written independently in `events.py` and `memory.py`
(both `_env_float`), `db/database.py` (`_env_int`) and `graph.py` (`_flag`). One implementation
keeps the house rule in a single place: a malformed or unset value must never stop the API from
starting, so it falls back to the caller's default instead of raising.

Note the deliberate difference from `runtime/envutil.py`, which looks similar but is NOT
interchangeable: there, a value below `minimum` falls back to the default (the knobs it reads are
budgets and token caps, where 0 or a negative would mean "no limit" — a fail-open the runtime must
refuse). Here, a value below `minimum` is **clamped** to it, because these knobs are pool sizes and
retention windows where the floor is the intended reading of "too small" — `EYE_RUN_RETENTION_SECONDS=-5`
means "retire immediately", not "use the 1-hour default". The two must stay separate; the packaging
direction (agent-runtime depends on control-plane, never the reverse) means runtime *could* import
this, but it deliberately does not.
"""
from __future__ import annotations

import os


def env_int(name: str, default: int, minimum: int = 0) -> int:
    """Read an int knob, clamped to `minimum` and never raising."""
    try:
        return max(minimum, int(os.getenv(name, "") or default))
    except (TypeError, ValueError):
        return default


def env_float(name: str, default: float, minimum: float = 0.0) -> float:
    """Read a float knob, clamped to `minimum` and never raising."""
    try:
        return max(minimum, float(os.getenv(name, "") or default))
    except (TypeError, ValueError):
        return default


def env_flag(name: str) -> bool:
    """Whether an opt-in knob is switched on. Unset means off, so a flag can only ever be enabled
    deliberately — anything unrecognised reads as off rather than as "something was set, so yes"."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}
