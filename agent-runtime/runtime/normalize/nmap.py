"""Parse nmap XML (-oX) into normalized services and findings.

Kept separate from the tool so it can be unit-tested against captured XML without Docker or nmap.

Handles one XML document describing many `<host>` elements natively — each host carries its own
`<address>`, so a range scan's services/findings are correctly attributed per-address rather than all
credited to the run's seed target. That matters for B2 (agent-runtime/runtime/tools/nmap.py): a range
target is now scanned as one `-sn`/light sweep across every address in the CIDR, and this is what
turns that single multi-host XML blob back into per-host topology.
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
    up_hosts: list[str] = []
    for host in root.findall("host"):
        # Prefer the IPv4/IPv6 address; fall back to the run's seed target if absent.
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else target

        status_el = host.find("status")
        if status_el is not None and status_el.get("state") == "up":
            up_hosts.append(address)

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

    if not out.services and not out.findings and up_hosts:
        # A pure host-discovery sweep (`-sn`) never scans a port, so services/findings are always
        # empty for one — the *only* signal it produces is which addresses answered. Without
        # surfacing that, a sweep that found 30 live hosts would look byte-for-byte identical to one
        # that found none ("0 services, 0 findings"), which defeats B2's "sweep once, then work from
        # the hosts it discovers" strategy: the agent would have nothing to work from. `note` is the
        # same free-text channel knowledge tools use to hand the model something other than raw
        # findings, so this reuses it rather than growing the ToolOutput shape.
        shown = ", ".join(up_hosts[:50])
        more = f" (+{len(up_hosts) - 50} more)" if len(up_hosts) > 50 else ""
        out.note = f"{len(up_hosts)} host(s) up: {shown}{more}"

    return out
