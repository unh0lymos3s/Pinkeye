"""Parse OWASP ZAP JSON output (zap-baseline.py -J). One finding per alert instance."""
from __future__ import annotations

import json

from app.models import Severity

from ..tools.base import ToolOutput
from .common import make_finding

# ZAP riskcode -> severity.
_RISK = {"3": Severity.high, "2": Severity.medium, "1": Severity.low, "0": Severity.info}


def parse_zap_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    out = ToolOutput()
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return out
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            severity = _RISK.get(str(alert.get("riskcode", "0")), Severity.info)
            cweid = alert.get("cweid")
            cwe = f"CWE-{cweid}" if cweid and str(cweid).isdigit() and int(cweid) > 0 else None
            # One finding per affected URL instance; fall back to the site name.
            instances = alert.get("instances") or [{"uri": site.get("@name", target)}]
            for inst in instances:
                out.findings.append(
                    make_finding(
                        engagement_id=engagement_id, run_id=run_id,
                        title=alert.get("alert", "ZAP alert"),
                        category="zap", target=inst.get("uri", target),
                        severity=severity, confidence=0.7, source_tool="zap", cwe=cwe,
                        evidence=(alert.get("desc") or "")[:300],
                    )
                )
    return out
