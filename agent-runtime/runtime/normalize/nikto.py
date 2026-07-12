"""Parse nikto XML output (`-Format xml`). Each <item> is a web-server finding."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from app.models import Severity

from ..tools.base import ToolOutput
from .common import make_finding


def parse_nikto_xml(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    out = ToolOutput()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return out
    for item in root.iter("item"):
        desc = (item.findtext("description") or "").strip()
        link = (item.findtext("namelink") or item.findtext("uri") or target).strip()
        # Nikto doesn't rate severity; treat server-config issues as low by default.
        out.findings.append(
            make_finding(
                engagement_id=engagement_id, run_id=run_id,
                title=desc[:120] or "nikto finding",
                category="nikto",
                target=link,
                severity=Severity.low,
                confidence=0.6,
                source_tool="nikto",
                evidence=desc,
            )
        )
    return out
