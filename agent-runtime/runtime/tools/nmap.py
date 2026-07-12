"""Nmap recon tool. Emits XML to stdout, which the normalizer turns into services + findings."""
from __future__ import annotations

from app.models import Intensity

from ..normalize.nmap import parse_nmap_xml
from .base import ToolOutput

# Intensity maps to nmap timing + port breadth. Higher intensity = louder + broader.
_INTENSITY_FLAGS = {
    Intensity.passive: ["-sT", "-T2", "--top-ports", "100"],
    Intensity.light: ["-sT", "-T3", "--top-ports", "1000"],
    Intensity.normal: ["-sS", "-sV", "-T4", "--top-ports", "1000"],
    Intensity.aggressive: ["-sS", "-sV", "-T4", "-p-"],
}


class NmapTool:
    name = "nmap"
    description = "TCP port and service discovery against a host or IP. Use for recon."
    image = "instrumentisto/nmap:latest"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        # -oX - writes XML to stdout; -Pn skips host discovery so filtered hosts still get scanned.
        return ["-Pn", *_INTENSITY_FLAGS[intensity], "-oX", "-", target]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_nmap_xml(raw, engagement_id=engagement_id, run_id=run_id, target=target)
