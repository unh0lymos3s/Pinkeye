"""Correlation: turn a flat list of findings into attack chains.

Two deterministic heuristics (no LLM required, so it is testable and reproducible):
  1. Per-host escalation — multiple findings on the same host become one chain, ordered by severity.
  2. Code-to-runtime — a SAST finding and a DAST/network finding that share a CWE become one chain,
     evidence that a weakness seen in source is also reachable at runtime.
A planning agent can layer richer reasoning on top later, but this gives a useful baseline.
"""
from __future__ import annotations

import uuid
from urllib.parse import urlparse

from .models import AttackChain, Finding, Severity, is_ip

_SEV_RANK = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}


def _host_of(target: str) -> str | None:
    """Best-effort host for a finding target; None for source locations (file:line)."""
    if target.startswith("http://") or target.startswith("https://"):
        return urlparse(target).hostname
    if is_ip(target):
        return target
    return None


def _max_sev(findings: list[Finding]) -> Severity:
    return max(findings, key=lambda f: _SEV_RANK[f.severity]).severity


def correlate(findings: list[Finding]) -> list[AttackChain]:
    if not findings:
        return []
    engagement_id = findings[0].engagement_id
    chains: list[AttackChain] = []

    # Heuristic 1: group by host, chain hosts that have more than one finding.
    by_host: dict[str, list[Finding]] = {}
    for f in findings:
        host = _host_of(f.target)
        if host:
            by_host.setdefault(host, []).append(f)
    for host, group in by_host.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda f: _SEV_RANK[f.severity], reverse=True)
        chains.append(
            AttackChain(
                id=str(uuid.uuid4()), engagement_id=engagement_id,
                title=f"Attack path on {host}", risk=_max_sev(ordered),
                steps=[f.dedup_key() for f in ordered],
                rationale=f"{len(ordered)} findings on {host}, escalating by severity.",
            )
        )

    # Heuristic 2: link source weaknesses to runtime findings by shared CWE.
    sast = [f for f in findings if f.category.startswith("sast:") and f.cwe]
    runtime = [f for f in findings if not f.category.startswith("sast:") and f.cwe]
    runtime_by_cwe: dict[str, list[Finding]] = {}
    for f in runtime:
        runtime_by_cwe.setdefault(f.cwe, []).append(f)
    for s in sast:
        matches = runtime_by_cwe.get(s.cwe)
        if not matches:
            continue
        group = [s, *matches]
        chains.append(
            AttackChain(
                id=str(uuid.uuid4()), engagement_id=engagement_id,
                title=f"Code-to-runtime: {s.cwe}", risk=_max_sev(group),
                steps=[f.dedup_key() for f in group],
                rationale=f"{s.cwe} found in source ({s.target}) and reachable at runtime.",
            )
        )

    # Highest-risk chains first.
    chains.sort(key=lambda c: _SEV_RANK[c.risk], reverse=True)
    return chains
