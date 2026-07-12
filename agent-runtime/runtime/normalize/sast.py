"""Parsers for static-analysis tools: semgrep, gitleaks, trivy. All emit JSON.

SAST findings target a source location (file:line) rather than a host, and carry CWE where the tool
provides it so they can later be correlated with runtime (DAST) findings on the same weakness class.
"""
from __future__ import annotations

import json

from app.models import Severity

from ..tools.base import ToolOutput
from .common import make_finding, to_severity


def _loc(path: str, start_line) -> str:
    return f"{path}:{start_line}" if start_line else path


def parse_semgrep_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    data = _load(raw)
    out = ToolOutput()
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = _first_cwe(meta.get("cwe"))
        out.findings.append(
            make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=r.get("check_id", "semgrep finding").split(".")[-1],
                category="sast:semgrep",
                target=_loc(r.get("path", target), r.get("start", {}).get("line")),
                severity=to_severity(extra.get("severity") or meta.get("impact")),
                confidence=0.7, source_tool="semgrep", cwe=cwe,
                evidence=(extra.get("message") or "")[:300],
            )
        )
    return out


def parse_gitleaks_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    data = _load(raw)
    # gitleaks emits a top-level JSON array of leaks.
    leaks = data if isinstance(data, list) else data.get("findings", [])
    out = ToolOutput()
    for leak in leaks:
        out.findings.append(
            make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=f"Secret leaked: {leak.get('RuleID', 'unknown rule')}",
                category="sast:secret",
                target=_loc(leak.get("File", target), leak.get("StartLine")),
                severity=Severity.high,  # a committed secret is high by default
                confidence=0.85, source_tool="gitleaks", cwe="CWE-798",
                evidence=(leak.get("Description") or leak.get("Match", ""))[:200],
            )
        )
    return out


def parse_trivy_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    data = _load(raw)
    out = ToolOutput()
    for res in data.get("Results", []):
        where = res.get("Target", target)
        for v in res.get("Vulnerabilities", []) or []:
            out.findings.append(
                make_finding(
                    engagement_id=engagement_id, run_id=run_id,
                    title=f"{v.get('PkgName', '')} {v.get('VulnerabilityID', '')}".strip(),
                    category="sast:dependency",
                    target=f"{where}:{v.get('PkgName', '')}",
                    severity=to_severity(v.get("Severity")),
                    confidence=0.8, source_tool="trivy",
                    cve=(v.get("VulnerabilityID") if str(v.get("VulnerabilityID", "")).startswith("CVE") else None),
                    evidence=(v.get("Title") or v.get("Description", ""))[:200],
                )
            )
    return out


def _load(raw: bytes | str):
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}


def _first_cwe(cwe) -> str | None:
    # semgrep metadata.cwe is often a string or list like "CWE-79: Cross-site Scripting".
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if isinstance(cwe, str) and cwe.upper().startswith("CWE"):
        return cwe.split(":")[0].strip().upper()
    return None
