"""DAST tools: dynamic web scanners that run against a live URL in the sandbox.

Each maps the shared {target, intensity} contract to the tool's real CLI and parses its structured
output into findings. Intensity influences breadth/rate so the agent can stay within scope limits.
"""
from __future__ import annotations

from app.models import Intensity

from app.secrets import load_secret

from ..normalize.ffuf import parse_ffuf_json
from ..normalize.nikto import parse_nikto_xml
from ..normalize.nuclei import parse_nuclei_jsonl
from ..normalize.zap import parse_zap_json
from .base import ToolOutput

_NUCLEI_SEVERITY = {
    Intensity.passive: "info,low",
    Intensity.light: "low,medium",
    Intensity.normal: "low,medium,high,critical",
    Intensity.aggressive: "info,low,medium,high,critical",
}


class NucleiTool:
    name = "nuclei"
    description = "Template-based web vulnerability scanner (CVEs, misconfigs). Target is a URL."
    image = "projectdiscovery/nuclei:latest"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        return ["-u", target, "-jsonl", "-silent", "-severity", _NUCLEI_SEVERITY[intensity]]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_nuclei_jsonl(raw, engagement_id=engagement_id, run_id=run_id, target=target)


class FfufTool:
    name = "ffuf"
    description = "Directory/endpoint discovery by fuzzing. Target is a base URL."
    image = "ghcr.io/ffuf/ffuf:latest"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        # The wordlist ships in the sandbox image; results go to stdout as JSON.
        rate = {"passive": "20", "light": "40", "normal": "100", "aggressive": "300"}[intensity.value]
        base = target.rstrip("/")
        return ["-u", f"{base}/FUZZ", "-w", "/wordlist.txt", "-of", "json", "-o", "-", "-s", "-rate", rate]

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_ffuf_json(raw, engagement_id=engagement_id, run_id=run_id, target=target)


class NiktoTool:
    name = "nikto"
    description = "Web-server misconfiguration and known-issue scanner. Target is a URL or host."
    image = "alpine/nikto:latest"

    def build_command(self, target: str, intensity: Intensity) -> list[str]:
        cmd = ["-h", target, "-Format", "xml", "-output", "-"]
        if intensity in (Intensity.passive, Intensity.light):
            cmd += ["-maxtime", "120s"]  # keep light scans bounded
        return cmd

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_nikto_xml(raw, engagement_id=engagement_id, run_id=run_id, target=target)


def _auth_header_args(auth: dict) -> list[str]:
    """Build ZAP 'replacer' options that inject an auth header into every request, enabling
    authenticated scanning. The header value is resolved from secrets by reference so the credential
    isn't embedded in the run config; it does appear in the sandboxed process args (a known trade-off).
    """
    header = auth.get("header_name", "Authorization")
    value = load_secret(auth["value_ref"]) if auth.get("value_ref") else auth.get("value", "")
    if not value:
        return []
    p = "replacer.full_list(0)"
    cfg = (
        f"{p}.description=auth;{p}.enabled=true;{p}.matchtype=REQ_HEADER;"
        f"{p}.matchstr={header};{p}.regex=false;{p}.replacement={value}"
    )
    return ["-z", cfg]


class ZapTool:
    name = "zap"
    description = (
        "OWASP ZAP dynamic web scan. Target is a URL. Supports authenticated scanning when the run "
        "provides an auth profile (header/token), covering surface behind a login."
    )
    image = "zaproxy/zap-stable:latest"
    wants_context = True  # reads the run's auth profile from context

    def build_command(self, target: str, intensity: Intensity, context: dict | None = None) -> list[str]:
        # zap-baseline for light scans, full active scan for higher intensity. JSON to stdout.
        script = "zap-full-scan.py" if intensity in (Intensity.normal, Intensity.aggressive) else "zap-baseline.py"
        cmd = [script, "-t", target, "-J", "/dev/stdout", "-I"]
        auth = (context or {}).get("auth")
        if auth:
            cmd += _auth_header_args(auth)
        return cmd

    def parse(self, raw: bytes, *, engagement_id: str, run_id: str, target: str) -> ToolOutput:
        return parse_zap_json(raw, engagement_id=engagement_id, run_id=run_id, target=target)


def dast_tools() -> list:
    return [NucleiTool(), FfufTool(), NiktoTool(), ZapTool()]
