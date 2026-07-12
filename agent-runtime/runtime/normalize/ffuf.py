"""Parse ffuf JSON output (`-of json`). Each result is a discovered endpoint."""
from __future__ import annotations

import json

from app.models import Severity

from ..tools.base import ToolOutput
from .common import make_finding


def parse_ffuf_json(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    out = ToolOutput()
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return out
    for r in data.get("results", []):
        url = r.get("url", target)
        status = r.get("status")
        out.findings.append(
            make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=f"Exposed endpoint {url} (HTTP {status})",
                category="exposed-endpoint",
                target=url,
                severity=Severity.info,
                confidence=0.9,
                source_tool="ffuf",
                evidence=f"status={status} length={r.get('length')}",
            )
        )
    return out
