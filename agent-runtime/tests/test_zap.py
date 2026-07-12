"""ZAP normalizer + authenticated-scan command construction."""
from app.models import Intensity
from runtime.normalize.zap import parse_zap_json
from runtime.tools.dast import ZapTool

ZAP_JSON = """{"site":[{"@name":"https://app.example.com","alerts":[
  {"alert":"SQL Injection","riskcode":"3","cweid":"89","desc":"tainted param",
   "instances":[{"uri":"https://app.example.com/search?q=1"}]},
  {"alert":"X-Frame-Options Not Set","riskcode":"1","cweid":"16","desc":"missing header",
   "instances":[{"uri":"https://app.example.com/"}]}
]}]}"""


def test_zap_parses_alerts_with_severity_and_cwe():
    out = parse_zap_json(ZAP_JSON, engagement_id="e1", run_id="r1", target="https://app.example.com")
    assert len(out.findings) == 2
    sqli = next(f for f in out.findings if "SQL" in f.title)
    assert sqli.severity.value == "high" and sqli.cwe == "CWE-89"
    assert sqli.target == "https://app.example.com/search?q=1"


def test_zap_unauthenticated_command_has_no_auth():
    cmd = ZapTool().build_command("https://app.example.com", Intensity.light, context=None)
    assert cmd[0] == "zap-baseline.py"
    assert "-z" not in cmd


def test_zap_authenticated_command_injects_header():
    ctx = {"auth": {"header_name": "Authorization", "value": "Bearer T0KEN"}}
    cmd = ZapTool().build_command("https://app.example.com", Intensity.light, context=ctx)
    joined = " ".join(cmd)
    assert "-z" in cmd
    assert "matchstr=Authorization" in joined and "Bearer T0KEN" in joined


def test_zap_full_scan_at_higher_intensity():
    cmd = ZapTool().build_command("https://app.example.com", Intensity.normal, context=None)
    assert cmd[0] == "zap-full-scan.py"
