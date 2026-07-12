"""Parse nuclei JSONL output (`-jsonl`). One JSON object per line, one finding each."""
from __future__ import annotations

import json

from ..tools.base import ToolOutput
from .common import make_finding, to_severity


def parse_nuclei_jsonl(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    out = ToolOutput()
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip banner/non-JSON lines nuclei may emit
        info = item.get("info", {})
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        cwes = classification.get("cwe-id") or []
        matched = item.get("matched-at") or item.get("host") or target
        finding = make_finding(
            engagement_id=engagement_id, run_id=run_id,
            title=info.get("name") or item.get("template-id", "nuclei match"),
            category=f"nuclei:{item.get('template-id', 'unknown')}",
            target=matched,
            severity=to_severity(info.get("severity")),
            confidence=0.8,
            source_tool="nuclei",
            cve=(cves[0] if cves else None),
            cwe=(cwes[0].upper() if cwes else None),
            evidence=str(item.get("matcher-name") or item.get("template-id", "")),
        )
        # nuclei often ships the CVSS vector in classification; keep it so enrichment scores exactly.
        finding.cvss_vector = classification.get("cvss-metrics")
        out.findings.append(finding)
    return out
