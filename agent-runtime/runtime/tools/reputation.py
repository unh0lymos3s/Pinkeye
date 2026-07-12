"""Reputation / malware-presence tools.

VirusTotalTool checks a file hash against VirusTotal to tell the agent whether a file already on (or
pulled from) a system is known malware. TlsCertTool inspects a host's TLS certificate. Together they
let the agent answer "is this artifact malicious, and is this endpoint's certificate trustworthy?".

Parsing is split into pure functions so it's unit-tested without network access.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
from datetime import datetime, timezone

from app.models import Severity
from app.secrets import load_secret

from ..normalize.common import make_finding
from .base import ToolOutput


# ---- VirusTotal ----

def parse_vt_stats(stats: dict) -> tuple[int, int]:
    """Return (malicious_or_suspicious, total_engines) from VT's last_analysis_stats block."""
    total = sum(int(v) for v in stats.values())
    flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    return flagged, total


def vt_note(hash_value: str, response: dict) -> tuple[str, bool]:
    """Turn a VT /files response into (note, is_malicious)."""
    stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    if stats is None:
        return f"VirusTotal has no record for {hash_value}.", False
    flagged, total = parse_vt_stats(stats)
    verdict = "MALICIOUS" if flagged else "clean"
    return f"VirusTotal: {hash_value} flagged by {flagged}/{total} engines ({verdict}).", flagged > 0


class VirusTotalTool:
    name = "virustotal"
    description = (
        "Check a file hash (md5/sha1/sha256) against VirusTotal for known-malware detections. "
        "Use to confirm whether a suspicious file is known malicious."
    )
    surface = "knowledge"
    local = True

    def run_local(self, *, target: str, intensity, context: dict, engagement_id: str, run_id: str) -> ToolOutput:
        api_key = load_secret("VT_API_KEY")
        if not api_key:
            return ToolOutput(note="VirusTotal API key not configured (set VT_API_KEY).")
        try:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/files/{target}",
                headers={"x-apikey": api_key},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            return ToolOutput(note=f"VirusTotal lookup failed for {target}: {exc}")

        note, malicious = vt_note(target, data)
        out = ToolOutput(note=note)
        if malicious:
            # A confirmed-malicious artifact is a high-severity finding attached to the hash.
            out.findings.append(
                make_finding(
                    engagement_id=engagement_id, run_id=run_id,
                    title=f"Known malware present (hash {target[:16]}…)",
                    category="malware-detection", target=target, severity=Severity.high,
                    confidence=0.9, source_tool="virustotal", evidence=note,
                )
            )
        return out


# ---- TLS certificate inspection ----

def parse_cert(cert: dict, host: str, now: datetime | None = None) -> ToolOutput:
    """Inspect an ssl.getpeercert() dict for validity issues."""
    now = now or datetime.now(timezone.utc)
    out = ToolOutput()

    def _name(field):
        # subject/issuer are tuples of RDN tuples: (((k, v),), ...). Flatten to a dict.
        return {k: v for rdn in field for (k, v) in rdn}

    subject = _name(cert.get("subject", ()))
    issuer = _name(cert.get("issuer", ()))
    not_after_raw = cert.get("notAfter")
    details = f"CN={subject.get('commonName', '?')} issuer={issuer.get('organizationName', '?')}"

    if not_after_raw:
        expires = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - now).days
        if days < 0:
            out.findings.append(make_finding(
                engagement_id="", run_id="", title=f"Expired TLS certificate on {host}",
                category="tls-cert", target=host, severity=Severity.medium, confidence=0.95,
                source_tool="tls_cert", cwe="CWE-295", evidence=f"expired {-days}d ago; {details}"))
        elif days < 14:
            out.findings.append(make_finding(
                engagement_id="", run_id="", title=f"TLS certificate expiring soon on {host}",
                category="tls-cert", target=host, severity=Severity.low, confidence=0.9,
                source_tool="tls_cert", evidence=f"expires in {days}d; {details}"))
        details += f" expires={not_after_raw}"

    # Self-signed: subject == issuer.
    if subject and subject == issuer:
        out.findings.append(make_finding(
            engagement_id="", run_id="", title=f"Self-signed TLS certificate on {host}",
            category="tls-cert", target=host, severity=Severity.low, confidence=0.9,
            source_tool="tls_cert", cwe="CWE-295", evidence=details))

    out.note = f"TLS certificate for {host}: {details}"
    return out


class TlsCertTool:
    name = "tls_cert"
    description = "Fetch and inspect a host's TLS certificate (expiry, issuer, self-signed). Target is host[:port]."
    surface = "network"  # connects to the target, so it is scope-guarded
    local = True

    def run_local(self, *, target: str, intensity, context: dict, engagement_id: str, run_id: str) -> ToolOutput:
        host, _, port = target.partition(":")
        port_num = int(port) if port else 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # we inspect the cert ourselves; don't fail on validation
            with ctx.wrap_socket(
                __import__("socket").create_connection((host, port_num), timeout=10),
                server_hostname=host,
            ) as sock:
                cert = sock.getpeercert()
        except Exception as exc:
            return ToolOutput(note=f"TLS certificate fetch failed for {target}: {exc}")

        out = parse_cert(cert or {}, host)
        # Stamp engagement/run onto the findings parse_cert built without them.
        for f in out.findings:
            f.engagement_id, f.run_id = engagement_id, run_id
        return out


def reputation_tools() -> list:
    return [VirusTotalTool(), TlsCertTool()]
