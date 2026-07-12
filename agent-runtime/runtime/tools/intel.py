"""Knowledge tools the agent calls to identify vulnerabilities and check for malware, offline where
possible. These run in-process (local=True) and don't touch a target, so their surface is
'knowledge' — authorized by a valid signed scope, no allowlist match needed.
"""
from __future__ import annotations

from app.cve_db import CveRepo

from .base import ToolOutput


def _split_product_version(target: str) -> tuple[str, str | None]:
    # Accept "nginx 1.18" or "nginx:1.18" or just "nginx".
    text = target.replace(":", " ").strip()
    parts = text.split()
    if len(parts) >= 2 and any(c.isdigit() for c in parts[-1]):
        return " ".join(parts[:-1]), parts[-1]
    return text, None


class CveLookupTool:
    name = "cve_lookup"
    description = (
        "Look up known CVEs for a product and optional version (e.g. 'openssh 7.2', 'log4j'). "
        "Use after fingerprinting a service to identify likely vulnerabilities."
    )
    surface = "knowledge"
    local = True

    def __init__(self, cve_repo: CveRepo):
        self._repo = cve_repo

    def run_local(self, *, target: str, intensity, context: dict, engagement_id: str, run_id: str) -> ToolOutput:
        product, version = _split_product_version(target)
        matches = self._repo.lookup(product, version)
        if not matches:
            return ToolOutput(note=f"No known CVEs found for '{target}'.")
        lines = [
            f"{m.cve_id} (CVSS {m.cvss_score}, {m.cwe or 'n/a'}): {m.description}"
            for m in matches
        ]
        return ToolOutput(note=f"Known CVEs for '{target}':\n" + "\n".join(lines))
