"""DAST normalizer tests: nuclei JSONL, ffuf JSON, nikto XML -> findings. No network needed."""
from runtime.normalize.ffuf import parse_ffuf_json
from runtime.normalize.nikto import parse_nikto_xml
from runtime.normalize.nuclei import parse_nuclei_jsonl

NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical",'
    '"classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["cwe-502"]}},'
    '"matched-at":"https://app.example.com/api"}\n'
    'not-json-banner-line\n'
    '{"template-id":"tech-detect","info":{"name":"nginx","severity":"info"},"host":"app.example.com"}\n'
)

FFUF_JSON = '{"results":[{"url":"https://app.example.com/admin","status":200,"length":1234},'\
            '{"url":"https://app.example.com/.git","status":403,"length":50}]}'

NIKTO_XML = """<niktoscan><scandetails>
  <item><description>Server leaks inodes via ETags</description>
        <namelink>https://app.example.com/</namelink></item>
</scandetails></niktoscan>"""


def test_nuclei_parses_cve_and_severity_skips_banner():
    out = parse_nuclei_jsonl(NUCLEI_JSONL, engagement_id="e1", run_id="r1", target="https://app.example.com")
    assert len(out.findings) == 2  # banner line skipped
    crit = next(f for f in out.findings if f.severity.value == "critical")
    assert crit.cve == "CVE-2021-44228"
    assert crit.cwe == "CWE-502"
    assert crit.target == "https://app.example.com/api"


def test_ffuf_parses_endpoints():
    out = parse_ffuf_json(FFUF_JSON, engagement_id="e1", run_id="r1", target="https://app.example.com")
    assert len(out.findings) == 2
    assert all(f.category == "exposed-endpoint" for f in out.findings)
    assert {f.target for f in out.findings} == {
        "https://app.example.com/admin", "https://app.example.com/.git"
    }


def test_nikto_parses_items():
    out = parse_nikto_xml(NIKTO_XML, engagement_id="e1", run_id="r1", target="https://app.example.com")
    assert len(out.findings) == 1
    assert out.findings[0].source_tool == "nikto"
    assert "ETags" in out.findings[0].evidence
