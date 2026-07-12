"""CVSS v3.1 scoring + MITRE ATT&CK mapping + finding enrichment."""
from app.attack import technique_for
from app.cvss import score_for_finding, score_from_vector, severity_from_score
from app.enrich import enrich_finding
from app.models import Finding, Severity


def test_cvss_known_vectors():
    # Log4Shell (CVE-2021-44228) canonical v3.1 vector scores 10.0.
    assert score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    # A classic no-impact vector scores 0.0.
    assert score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    # A medium example (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N) ~ 5.4.
    assert 5.0 <= score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N") <= 5.5


def test_severity_from_score_bands():
    assert severity_from_score(9.8) == Severity.critical
    assert severity_from_score(7.0) == Severity.high
    assert severity_from_score(4.0) == Severity.medium
    assert severity_from_score(0.1) == Severity.low
    assert severity_from_score(0.0) == Severity.info


def test_score_falls_back_to_severity_without_vector():
    assert score_for_finding(None, Severity.critical) == 9.5
    assert score_for_finding("garbage-not-a-vector", Severity.high) == 7.5


def test_attack_mapping_by_cwe_and_category():
    assert technique_for("CWE-89", "nuclei:x")[0] == "T1190"       # SQLi -> exploit public app
    assert technique_for(None, "open-port")[0] == "T1046"          # by category
    assert technique_for(None, "sast:other")[0] == "T1552"         # prefix fallback (sast -> creds)
    assert technique_for(None, "totally-unknown") is None


def test_enrich_sets_cvss_and_attack():
    f = Finding(id="1", engagement_id="e1", run_id="r1", title="SQLi", category="nuclei:sqli",
                target="https://x/y", severity=Severity.high, cwe="CWE-89")
    enrich_finding(f)
    assert f.cvss_score == 7.5  # from severity fallback (no vector)
    assert f.attack_technique == "T1190"
    assert f.attack_technique_name == "Exploit Public-Facing Application"
