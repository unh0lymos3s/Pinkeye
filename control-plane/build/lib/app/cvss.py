"""CVSS v3.1 base-score computation and severity mapping.

Tools emit CVSS in different ways: some give a vector string, some only a severity word. This module
computes a base score from a v3.1 vector (the real formula) and, failing that, falls back to a
representative score for a severity label so every finding gets a comparable number.
"""
from __future__ import annotations

from .models import Severity

# Metric value weights from the CVSS v3.1 specification.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_SEVERITY_FALLBACK = {
    Severity.critical: 9.5,
    Severity.high: 7.5,
    Severity.medium: 5.0,
    Severity.low: 3.0,
    Severity.info: 0.0,
}


def _roundup(x: float) -> float:
    # CVSS "roundup": round to one decimal, always up. Implemented per the spec's integer trick.
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def score_from_vector(vector: str) -> float | None:
    """Return the CVSS v3.1 base score for a vector like 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'."""
    parts = dict(
        p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS")
    )
    try:
        av, ac, ui = _AV[parts["AV"]], _AC[parts["AC"]], _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min((impact + exploitability) * (1.08 if scope_changed else 1.0), 10.0)
    return _roundup(raw)


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0.0:
        return Severity.low
    return Severity.info


def score_for_finding(vector: str | None, severity: Severity) -> float:
    """Best available CVSS score: from the vector if present, else a severity-based fallback."""
    if vector:
        s = score_from_vector(vector)
        if s is not None:
            return s
    return _SEVERITY_FALLBACK[severity]
