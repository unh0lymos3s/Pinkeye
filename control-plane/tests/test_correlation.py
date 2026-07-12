"""Phase 5 tests: correlation heuristics, report rendering, and validation gating."""
import uuid

from app.correlation import correlate
from app.models import Finding, Severity
from app.report import generate_report
from app.validation import ExploitNotAllowed, MetasploitClient, should_confirm


def mk(category, target, severity=Severity.medium, cwe=None):
    return Finding(
        id=str(uuid.uuid4()), engagement_id="e1", run_id="r1", title=f"{category} on {target}",
        category=category, severity=severity, target=target, cwe=cwe, source_tool=category.split(":")[0],
    )


def test_per_host_chain_groups_multiple_findings():
    findings = [
        mk("open-port", "10.0.0.5", Severity.low),
        mk("nuclei:cve", "10.0.0.5", Severity.critical),
        mk("open-port", "10.0.0.9", Severity.low),  # lone finding -> no chain
    ]
    chains = correlate(findings)
    host_chains = [c for c in chains if c.title == "Attack path on 10.0.0.5"]
    assert len(host_chains) == 1
    assert host_chains[0].risk == Severity.critical  # ordered by max severity
    assert len(host_chains[0].steps) == 2


def test_code_to_runtime_chain_links_by_cwe():
    findings = [
        mk("sast:semgrep", "app/db.py:42", Severity.high, cwe="CWE-89"),
        mk("nuclei:sqli", "https://app.example.com/q", Severity.high, cwe="CWE-89"),
    ]
    chains = correlate(findings)
    assert any(c.title == "Code-to-runtime: CWE-89" for c in chains)


def test_report_contains_key_sections():
    findings = [mk("nuclei:cve", "https://x/y", Severity.high, cwe="CWE-79")]
    metrics = {"cves_identified": 1, "exposed_endpoints": 3, "hosts": 2, "open_issues": 1, "runs": 1}
    md = generate_report("acme", metrics, findings, correlate(findings))
    assert "# Assessment Report — acme" in md
    assert "## Summary" in md
    assert "CVEs identified: **1**" in md
    assert "## Findings by severity" in md


def test_should_confirm_requires_corroboration_and_confidence():
    assert should_confirm("suspected", 0.9, times_seen=2)
    assert not should_confirm("suspected", 0.9, times_seen=1)   # only seen once
    assert not should_confirm("suspected", 0.5, times_seen=3)   # low confidence
    assert not should_confirm("false_positive", 0.99, times_seen=9)


def test_metasploit_is_gated():
    disabled = MetasploitClient()
    assert "skipped" in disabled.check("mod", "10.0.0.5")  # check is a no-op when disabled
    try:
        disabled.exploit("mod", "10.0.0.5")
        assert False, "exploit should be refused"
    except ExploitNotAllowed:
        pass
    # Even enabled, exploitation needs the explicit second flag.
    enabled = MetasploitClient(enabled=True)
    try:
        enabled.exploit("mod", "10.0.0.5")
        assert False, "exploit should still be refused without allow_exploit"
    except ExploitNotAllowed:
        pass
    assert MetasploitClient(enabled=True, allow_exploit=True).exploit("mod", "x")["action"] == "exploit"
