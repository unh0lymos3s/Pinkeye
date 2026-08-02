"""Parse trivy `fs` JSON scans into dependency-CVE findings.

Split out of the old combined `sast.py` normalizer (round 6) alongside gitleaks.py — see that module's
docstring for why the split happened. Trivy's stdout was never the problem (unlike gitleaks it writes
its report to stdout just fine); what was broken is that its scan never ran at all inside the sandbox,
because the vulnerability-DB download has nowhere to put a temp dir on a read-only root filesystem
(see ../tools/sast.py for the fix). Verified against genuine `trivy fs --format json` output (v0.72.0)
from a real, locked-down container run with a writable /tmp tmpfs — see the round-6 report.
"""
from __future__ import annotations

import json

from ..tools.base import ToolOutput
from .common import make_finding, to_severity


def parse_trivy_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    data = _load(raw)
    out = ToolOutput()
    for res in data.get("Results", []) or []:
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
