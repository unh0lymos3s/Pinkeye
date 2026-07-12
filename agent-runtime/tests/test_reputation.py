"""VirusTotal + TLS cert parsing (pure functions, no network)."""
from datetime import datetime, timezone

from runtime.tools.reputation import parse_cert, parse_vt_stats, vt_note

VT_MALICIOUS = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 42, "suspicious": 3, "harmless": 0, "undetected": 25}}}}
VT_CLEAN = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 0, "suspicious": 0, "harmless": 5, "undetected": 65}}}}


def test_vt_stats_and_note():
    flagged, total = parse_vt_stats(VT_MALICIOUS["data"]["attributes"]["last_analysis_stats"])
    assert flagged == 45 and total == 70
    note, malicious = vt_note("abc123", VT_MALICIOUS)
    assert malicious and "45/70" in note and "MALICIOUS" in note
    _, clean = vt_note("def456", VT_CLEAN)
    assert not clean


def test_vt_note_unknown_hash():
    note, malicious = vt_note("zzz", {"data": {"attributes": {}}})
    assert not malicious and "no record" in note.lower()


def _cert(cn, issuer_org, not_after, issuer_cn=None):
    return {
        "subject": ((("commonName", cn),),),
        "issuer": ((("organizationName", issuer_org),), (("commonName", issuer_cn or issuer_org),)),
        "notAfter": not_after,
    }


def test_expired_cert_flagged():
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    out = parse_cert(_cert("example.com", "Lets Encrypt", "Jan  1 12:00:00 2025 GMT"), "example.com", now)
    assert any("Expired" in f.title for f in out.findings)
    assert any(f.cwe == "CWE-295" for f in out.findings)


def test_valid_cert_no_findings():
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    out = parse_cert(_cert("example.com", "DigiCert", "Dec 31 12:00:00 2025 GMT"), "example.com", now)
    assert out.findings == []
    assert "example.com" in out.note


def test_self_signed_flagged():
    now = datetime(2025, 6, 1, tzinfo=timezone.utc)
    # subject == issuer -> self-signed.
    cert = {"subject": ((("commonName", "box"),),), "issuer": ((("commonName", "box"),),),
            "notAfter": "Dec 31 12:00:00 2025 GMT"}
    out = parse_cert(cert, "box", now)
    assert any("Self-signed" in f.title for f in out.findings)
