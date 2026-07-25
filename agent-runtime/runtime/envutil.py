"""Shared environment-variable parsers.

Four near-identical copies of these lived in `agent.py`, `llm/openai_compat.py`, `llm/claude.py`
(inline `_f`/`_i`) and `llm/config.py`. One implementation keeps the house rule in a single place:
an unset, blank, or unparseable value falls back to the caller's default rather than raising or
disabling a cap — and so does a value below `minimum`, when one is given (used for the budgets and
token caps, where 0 or a negative would mean "no limit").
"""
from __future__ import annotations

import os


def env_int(name: str, default: int, minimum: int | None = None) -> int:
    """Read an int from the environment, falling back to `default` on anything unusable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if minimum is not None and value < minimum:
        return default
    return value


def env_float(name: str, default: float, minimum: float | None = None) -> float:
    """Read a float from the environment, falling back to `default` on anything unusable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if minimum is not None and value < minimum:
        return default
    return value
