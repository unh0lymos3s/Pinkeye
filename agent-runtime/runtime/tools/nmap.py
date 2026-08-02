"""Nmap recon tool. Emits XML to stdout, which the normalizer turns into services + findings.

B2: a *range* target (a CIDR with more than one address) needs a completely different command shape
than a single host, or the agent loop burns its whole tool-call budget on one call. `-Pn` tells nmap
to skip host discovery and scan every address as if it were up — sane for one host, catastrophic for
a /24: 256 addresses each getting a full `--top-ports 1000` TCP connect/SYN scan, which is enormous or
times out, and either way teaches the model nothing before the budget (or the wall clock) runs out.
For a range we drop `-Pn` and run a cheap sweep instead — `-sn` (just find out what's up) at
passive/light, or a light top-ports scan at normal/aggressive — so one call returns a manageable
result the agent can then work from host-by-host. Single-host targets are untouched: same flags as
before, `-Pn` included.
"""
from __future__ import annotations

import ipaddress

from app.models import Intensity

from ..envutil import env_int
from ..normalize.nmap import parse_nmap_xml
from .base import ToolOutput

# Intensity maps to nmap timing + port breadth. Higher intensity = louder + broader. Single-host only
# — see _SWEEP_FLAGS for the range case, which never uses -Pn.
_INTENSITY_FLAGS = {
    Intensity.passive: ["-sT", "-T2", "--top-ports", "100"],
    Intensity.light: ["-sT", "-T3", "--top-ports", "1000"],
    Intensity.normal: ["-sS", "-sV", "-T4", "--top-ports", "1000"],
    Intensity.aggressive: ["-sS", "-sV", "-T4", "-p-"],
}

# Range (multi-address target) flags. -sn is a pure host-discovery sweep (no port scan at all) at the
# quieter intensities; normal/aggressive still scan, but a narrow top-ports pass instead of the
# single-host table, which would be -p- or --top-ports 1000 per host across the whole range.
_SWEEP_FLAGS = {
    Intensity.passive: ["-sn"],
    Intensity.light: ["-sn"],
    Intensity.normal: ["-T4", "--top-ports", "100"],
    Intensity.aggressive: ["-T4", "--top-ports", "100"],
}

# Refuse a sweep against a range wider than this many addresses rather than silently truncating it or
# letting it run indefinitely. Env-tunable per engagement; the default keeps a single call bounded to
# roughly a /22.
_DEFAULT_MAX_SWEEP_HOSTS = 1024


def _as_network(target: str):
    """`target` as an ip_network if it parses as one, else None (a hostname, or garbage)."""
    try:
        return ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return None


class NmapTool:
    name = "nmap"
    description = "TCP port and service discovery against a host or IP. Use for recon."
    image = "instrumentisto/nmap:latest"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        # -oX - writes XML to stdout in every case.
        network = _as_network(target)
        if network is not None and network.num_addresses > 1:
            max_hosts = env_int("EYE_MAX_SWEEP_HOSTS", _DEFAULT_MAX_SWEEP_HOSTS, minimum=1)
            if network.num_addresses > max_hosts:
                # Never silently truncate the range — that would scan a different (and unreviewed)
                # target than the one authorized. Surfaced to the model via StepResult.error ->
                # `_summarize`'s "tool error: {...}" prefix, so it reads as an actionable instruction.
                raise ValueError(
                    f"range too large ({network.num_addresses} addresses); scan a smaller prefix"
                )
            return [*_SWEEP_FLAGS[intensity], "-oX", "-", target]
        # -Pn skips host discovery so a filtered single host still gets scanned.
        return ["-Pn", *_INTENSITY_FLAGS[intensity], "-oX", "-", target]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_nmap_xml(raw, engagement_id=engagement_id, run_id=run_id, target=target)
