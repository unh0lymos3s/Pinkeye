"""CVE lookup tool: product/version parsing + note generation, with a fake repo (no DB)."""
from app.cve_db import CveRecord
from app.models import Intensity
from runtime.tools.intel import CveLookupTool, _split_product_version


class FakeRepo:
    def __init__(self, records):
        self._records = records
        self.calls = []

    def lookup(self, product, version=None, limit=25):
        self.calls.append((product, version))
        return self._records


def test_product_version_splitting():
    assert _split_product_version("openssh 7.2") == ("openssh", "7.2")
    assert _split_product_version("apache struts 2.5.10") == ("apache struts", "2.5.10")
    assert _split_product_version("log4j") == ("log4j", None)
    assert _split_product_version("nginx:1.18") == ("nginx", "1.18")


def test_cve_tool_returns_matches_as_note():
    rec = CveRecord("CVE-2021-44228", "log4j", "2.0-2.14.1", 10.0, None, "CWE-502", "Log4Shell RCE")
    tool = CveLookupTool(FakeRepo([rec]))
    out = tool.run_local(target="log4j 2.14", intensity=Intensity.light, context={},
                         engagement_id="e1", run_id="r1")
    assert "CVE-2021-44228" in out.note and "10.0" in out.note
    assert out.findings == []  # knowledge tool informs, doesn't persist findings


def test_cve_tool_handles_no_matches():
    out = CveLookupTool(FakeRepo([])).run_local(
        target="unknownware", intensity=Intensity.light, context={}, engagement_id="e1", run_id="r1"
    )
    assert "No known CVEs" in out.note
