"""Parse nmap XML (-oX) into normalized services and findings.

Kept separate from the tool so it can be unit-tested against captured XML without Docker or nmap.
"""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET

from app.models import Finding, Severity

from ..tools.base import ServiceObservation, ToolOutput


def parse_nmap_xml(raw: bytes | str, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    root = ET.fromstring(raw)

    out = ToolOutput()
    for host in root.findall("host"):
        # Prefer the IPv4/IPv6 address; fall back to the run's seed target if absent.
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else target

        for port_el in host.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            number = int(port_el.get("portid"))
            proto = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            service = svc_el.get("name", "") if svc_el is not None else ""
            product = svc_el.get("product", "") if svc_el is not None else ""

            out.services.append(
                ServiceObservation(
                    address=address, port=number, proto=proto, service=service, product=product
                )
            )
            # Each open port is a low-severity, high-confidence finding: it's an observed fact.
            out.findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement_id,
                    run_id=run_id,
                    title=f"Open port {number}/{proto}" + (f" ({service})" if service else ""),
                    category="open-port",
                    severity=Severity.low if service else Severity.info,
                    confidence=0.95,
                    target=address,
                    evidence=f"{number}/{proto} {service} {product}".strip(),
                    source_tool="nmap",
                )
            )
    return out
