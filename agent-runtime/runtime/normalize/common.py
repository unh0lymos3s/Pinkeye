"""Helpers shared by tool normalizers: severity mapping and finding construction."""
from __future__ import annotations

import uuid

from app.models import Finding, Severity

_SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "moderate": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "informational": Severity.info,
    "unknown": Severity.info,
    # Semgrep (and SARIF-style) tools grade by ERROR/WARNING/INFO rather than critical..low.
    "error": Severity.high,
    "warning": Severity.medium,
    "note": Severity.info,
}


def to_severity(value: str | None) -> Severity:
    return _SEVERITY_MAP.get((value or "").strip().lower(), Severity.info)


def make_finding(
    *, engagement_id: str, run_id: str, title: str, category: str, target: str,
    severity: Severity = Severity.info, confidence: float = 0.6, source_tool: str = "",
    cwe: str | None = None, cve: str | None = None, evidence: str = "",
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()), engagement_id=engagement_id, run_id=run_id, title=title,
        category=category, target=target, severity=severity, confidence=confidence,
        source_tool=source_tool, cwe=cwe, cve=cve, evidence=evidence,
    )
