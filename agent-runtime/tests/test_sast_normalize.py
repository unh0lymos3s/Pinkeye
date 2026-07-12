"""SAST normalizer tests (semgrep, gitleaks, trivy) plus artifact-scope authorization."""
from datetime import datetime, timedelta, timezone

from app.models import Intensity, Scope
from app.scope import authorize, sign_scope
from runtime.normalize.sast import parse_gitleaks_json, parse_semgrep_json, parse_trivy_json

SEMGREP = (
    '{"results":[{"check_id":"python.lang.security.audit.sql-injection","path":"app/db.py",'
    '"start":{"line":42},"extra":{"severity":"ERROR","message":"tainted SQL",'
    '"metadata":{"cwe":["CWE-89: SQL Injection"]}}}]}'
)
GITLEAKS = '[{"RuleID":"aws-access-key","File":"config.py","StartLine":10,"Description":"AWS key"}]'
TRIVY = (
    '{"Results":[{"Target":"requirements.txt","Vulnerabilities":['
    '{"PkgName":"requests","VulnerabilityID":"CVE-2023-32681","Severity":"MEDIUM","Title":"proxy leak"}]}]}'
)


def test_semgrep_maps_cwe_and_location():
    out = parse_semgrep_json(SEMGREP, engagement_id="e1", run_id="r1", target="/src")
    f = out.findings[0]
    assert f.cwe == "CWE-89"
    assert f.target == "app/db.py:42"
    assert f.category == "sast:semgrep"


def test_gitleaks_flags_secret_high():
    out = parse_gitleaks_json(GITLEAKS, engagement_id="e1", run_id="r1", target="/src")
    assert out.findings[0].severity.value == "high"
    assert out.findings[0].cwe == "CWE-798"
    assert out.findings[0].target == "config.py:10"


def test_trivy_extracts_cve():
    out = parse_trivy_json(TRIVY, engagement_id="e1", run_id="r1", target="/src")
    assert out.findings[0].cve == "CVE-2023-32681"


def test_artifact_scope_authorization():
    now = datetime.now(timezone.utc)
    scope = Scope(
        allowed_artifacts=["/repos/app"],
        not_before=now - timedelta(hours=1), not_after=now + timedelta(hours=1),
        max_intensity=Intensity.normal,
    )
    scope.signature = sign_scope(scope)
    # In-scope source path is allowed; a path outside the allowed prefix is denied.
    assert authorize(scope, "/repos/app/src", Intensity.light, surface="artifact").allowed
    assert not authorize(scope, "/etc/passwd", Intensity.light, surface="artifact").allowed
    # An artifact path must NOT satisfy a network-surface check.
    assert not authorize(scope, "/repos/app", Intensity.light, surface="network").allowed
