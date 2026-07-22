"""MCP integration: real stdio protocol roundtrip, result mapping, and — most importantly — that an
MCP-backed tool still runs behind the scope guard and offensive-flag gate before the server is called.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

from app.audit import EventType, MemoryAuditSink
from app.models import Engagement, Intensity, Run, RunStatus, Scope
from app.scope import sign_scope
from runtime.mcp import MCPClient, MCPError, wrap_tools_with_mcp
from runtime.mcp.backend import MCPBackedTool, MCPServerSpec
from runtime.mcp.config import load_mcp_config
from runtime.orchestrator import execute_tool_step, run_scan
from runtime.tools.nmap import NmapTool

# A tiny but real MCP stdio server: does the initialize handshake, then answers tools/call by echoing
# a structured finding that references the target it was given.
FAKE_SERVER = r"""
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        out = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "fake", "version": "0"}}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": out}) + "\n")
        sys.stdout.flush()
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        out = {"tools": [{"name": "scan"}]}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": out}) + "\n")
        sys.stdout.flush()
    elif method == "tools/call":
        args = msg["params"]["arguments"]
        finding = [{"name": "demo-vuln", "severity": "high", "cve": "CVE-2021-0001", "matched-at": args.get("target")}]
        out = {"content": [{"type": "text", "text": json.dumps(finding)}], "isError": False}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": out}) + "\n")
        sys.stdout.flush()
"""


def make_engagement(cidr="10.0.0.0/24", **flags) -> Engagement:
    now = datetime.now(timezone.utc)
    scope = Scope(
        allowed_cidrs=[cidr], allowed_domains=[],
        not_before=now - timedelta(hours=1), not_after=now + timedelta(hours=1),
        max_intensity=Intensity.normal, **flags,
    )
    scope.signature = sign_scope(scope)
    return Engagement(id="e1", name="test", scope=scope)


class FakeGraph:
    def __init__(self):
        self.services, self.findings = [], []

    def upsert_service(self, *args):
        self.services.append(args)

    def record_finding(self, finding):
        self.findings.append(finding)


class FakeMCPClient:
    """Injectable stand-in for MCPClient. Records calls so tests can assert the server was (not) hit."""

    def __init__(self, result=None, error=None):
        self._result = result if result is not None else _text_result("ok")
        self._error = error
        self.calls: list = []
        self.started = self.closed = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def start(self):
        self.started = True

    def close(self):
        self.closed = True

    def call_tool(self, name, arguments):
        self.calls.append((name, dict(arguments)))
        if self._error:
            raise self._error
        return self._result


def _text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _spec(**kw) -> MCPServerSpec:
    base = {"command": sys.executable, "tool": "scan", "args": ["-c", FAKE_SERVER]}
    base.update(kw)
    return MCPServerSpec.from_dict(base)


# ---------------------------------------------------------------------------------------------------
# Real protocol: spawn the fake stdio server and complete a full initialize -> tools/call roundtrip.
# ---------------------------------------------------------------------------------------------------
def test_mcp_client_stdio_roundtrip():
    with MCPClient(sys.executable, ["-c", FAKE_SERVER], timeout=15) as client:
        tools = client.list_tools()
        assert any(t.get("name") == "scan" for t in tools)
        result = client.call_tool("scan", {"target": "10.0.0.5"})
    payload = json.loads(result["content"][0]["text"])
    assert payload[0]["cve"] == "CVE-2021-0001"
    assert payload[0]["matched-at"] == "10.0.0.5"


def test_mcp_client_timeout_on_silent_server():
    # A server that reads but never answers must trip the wall-clock ceiling, not hang forever.
    silent = "import sys\nfor _ in sys.stdin:\n    pass\n"
    with pytest.raises(MCPError):
        MCPClient(sys.executable, ["-c", silent], timeout=1).start()


# ---------------------------------------------------------------------------------------------------
# Result mapping: structured JSON -> findings; free text -> one informational finding + note.
# ---------------------------------------------------------------------------------------------------
def test_backed_tool_maps_structured_findings():
    result = _text_result(json.dumps([
        {"name": "sqli", "severity": "critical", "cve": ["CVE-2020-1"], "matched-at": "http://x/y"},
        {"title": "xss", "severity": "medium", "cwe": "cwe-79"},
    ]))
    tool = MCPBackedTool(NmapTool(), _spec(), client_factory=lambda: FakeMCPClient(result))
    out = tool.run_mcp(target="10.0.0.5", intensity=Intensity.light, context={},
                       engagement_id="e1", run_id="r1")
    assert len(out.findings) == 2
    crit = out.findings[0]
    assert crit.severity.value == "critical" and crit.cve == "CVE-2020-1"
    assert crit.target == "http://x/y" and crit.source_tool == "nmap"
    assert out.findings[1].cwe == "CWE-79"


def test_backed_tool_wraps_unstructured_output():
    tool = MCPBackedTool(NmapTool(), _spec(),
                         client_factory=lambda: FakeMCPClient(_text_result("host is up; 22/tcp open")))
    out = tool.run_mcp(target="10.0.0.5", intensity=Intensity.light, context={},
                       engagement_id="e1", run_id="r1")
    assert len(out.findings) == 1
    assert "22/tcp open" in out.note
    assert out.findings[0].target == "10.0.0.5"


def test_backed_tool_extracts_findings_key():
    result = _text_result(json.dumps({"findings": [{"name": "a", "severity": "low"}]}))
    tool = MCPBackedTool(NmapTool(), _spec(), client_factory=lambda: FakeMCPClient(result))
    out = tool.run_mcp(target="t", intensity=Intensity.light, context={},
                       engagement_id="e1", run_id="r1")
    assert len(out.findings) == 1 and out.findings[0].severity.value == "low"


# ---------------------------------------------------------------------------------------------------
# SAFETY: the scope guard and flag gate run BEFORE the MCP server is ever contacted.
# ---------------------------------------------------------------------------------------------------
def test_backed_tool_denied_before_server_is_called():
    eng = make_engagement(cidr="192.168.0.0/24")  # 10.0.0.5 is out of scope
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    fake = FakeMCPClient()
    tool = MCPBackedTool(NmapTool(), _spec(), client_factory=lambda: fake)
    audit = MemoryAuditSink()

    step = execute_tool_step(eng, run, tool, "10.0.0.5", Intensity.light,
                             sandbox=None, graph=FakeGraph(), audit=audit)

    assert step.allowed is False
    assert fake.calls == []  # the server was never contacted
    assert any(e.type == EventType.scope_decision and e.allowed is False for e in audit.events)


def test_backed_tool_runs_when_in_scope():
    eng = make_engagement()
    run = Run(id="r2", engagement_id="e1", target="10.0.0.5")
    fake = FakeMCPClient(_text_result(json.dumps([{"name": "v", "severity": "high"}])))
    tool = MCPBackedTool(NmapTool(), _spec(), client_factory=lambda: fake)
    graph, audit = FakeGraph(), MemoryAuditSink()

    step = execute_tool_step(eng, run, tool, "10.0.0.5", Intensity.light,
                             sandbox=None, graph=graph, audit=audit)

    assert step.allowed and step.error is None
    assert fake.calls == [("scan", {"target": "10.0.0.5"})]
    assert len(graph.findings) == 1
    assert any(e.type == EventType.tool_finished and "mcp[" in (e.detail or "") for e in audit.events)


def test_backed_tool_preserves_requires_flag_gate():
    # Wrapping must not strip an offensive tool's flag gate: without allow_exploit it stays denied.
    class FakeExploit:
        name, description, image = "exploit", "", ""
        requires_flag = "allow_exploit"

    eng = make_engagement()  # allow_exploit defaults False
    run = Run(id="r3", engagement_id="e1", target="10.0.0.5")
    fake = FakeMCPClient()
    tool = MCPBackedTool(FakeExploit(), _spec(tool="run"), client_factory=lambda: fake)
    assert tool.requires_flag == "allow_exploit"

    step = execute_tool_step(eng, run, tool, "10.0.0.5", Intensity.light,
                             sandbox=None, graph=FakeGraph(), audit=MemoryAuditSink())
    assert step.allowed is False and fake.calls == []


def test_mcp_error_surfaces_as_step_error():
    eng = make_engagement()
    run = Run(id="r4", engagement_id="e1", target="10.0.0.5")
    fake = FakeMCPClient(error=MCPError("server exploded"))
    tool = MCPBackedTool(NmapTool(), _spec(), client_factory=lambda: fake)

    step = execute_tool_step(eng, run, tool, "10.0.0.5", Intensity.light,
                             sandbox=None, graph=FakeGraph(), audit=MemoryAuditSink())
    assert step.allowed is True and step.error and "server exploded" in step.error


# ---------------------------------------------------------------------------------------------------
# Config + wrapping.
# ---------------------------------------------------------------------------------------------------
def test_wrap_tools_with_mcp_replaces_only_configured(monkeypatch):
    monkeypatch.setenv("EYE_MCP_SERVERS", json.dumps({
        "nmap": {"command": "npx", "args": ["-y", "nmap-mcp"], "tool": "run_nmap_scan"},
    }))
    from runtime.tools.dast import NucleiTool

    specs = load_mcp_config()
    assert "nmap" in specs and specs["nmap"].tool == "run_nmap_scan"

    wrapped = wrap_tools_with_mcp([NmapTool(), NucleiTool()], specs)
    by_name = {t.name: t for t in wrapped}
    assert isinstance(by_name["nmap"], MCPBackedTool)
    assert not isinstance(by_name["nuclei"], MCPBackedTool)  # untouched, stays on the sandbox path


def test_no_config_leaves_tools_unchanged(monkeypatch):
    monkeypatch.delenv("EYE_MCP_SERVERS", raising=False)
    monkeypatch.delenv("EYE_MCP_CONFIG", raising=False)
    tools = [NmapTool()]
    assert wrap_tools_with_mcp(tools) is tools  # identity: default path is byte-for-byte unchanged


def test_path_list_target_mode_wraps_file(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("x = 1\n")
    fake = FakeMCPClient(_text_result("ok"))
    tool = MCPBackedTool(NmapTool(), _spec(target_arg="code_files", target_mode="path_list"),
                         client_factory=lambda: fake)
    tool.run_mcp(target=str(f), intensity=Intensity.light, context={},
                 engagement_id="e1", run_id="r1")
    assert fake.calls[0][1] == {"code_files": [{"path": str(f)}]}


def test_path_list_target_mode_expands_directory(tmp_path):
    (tmp_path / "a.py").write_text("1")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("2")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("ignored")  # hidden dir must be skipped
    fake = FakeMCPClient(_text_result("ok"))
    tool = MCPBackedTool(NmapTool(), _spec(target_arg="code_files", target_mode="path_list"),
                         client_factory=lambda: fake)
    tool.run_mcp(target=str(tmp_path), intensity=Intensity.light, context={},
                 engagement_id="e1", run_id="r1")
    paths = {p["path"] for p in fake.calls[0][1]["code_files"]}
    assert paths == {str(tmp_path / "a.py"), str(tmp_path / "sub" / "b.py")}


def test_maps_nested_severity_and_cwe():
    # semgrep-shaped item: severity/message under `extra`, cwe under extra.metadata, check_id title.
    result = _text_result(json.dumps({"results": [
        {"check_id": "python.lang.security.eval", "path": "/src/app.py",
         "extra": {"severity": "ERROR", "message": "eval is dangerous",
                   "metadata": {"cwe": ["CWE-95: Eval Injection"]}}},
    ]}))
    tool = MCPBackedTool(NmapTool(), _spec(), client_factory=lambda: FakeMCPClient(result))
    out = tool.run_mcp(target="/src", intensity=Intensity.light, context={},
                       engagement_id="e1", run_id="r1")
    f = out.findings[0]
    assert f.title == "python.lang.security.eval" and f.cwe == "CWE-95"
    assert f.severity.value == "high"  # semgrep ERROR -> high
    assert f.target == "/src/app.py" and "eval is dangerous" in f.evidence


def test_maps_snyk_code_issue():
    # Snyk `snyk_code_scan` shape: top-level `issues`, plural `cwes`/`cves` lists, `filePath` location.
    result = _text_result(json.dumps({"issues": [
        {"title": "SQL Injection", "severity": "high", "cwes": ["CWE-89"], "cves": [],
         "filePath": "/src/app.py", "message": "tainted input reaches query"},
    ]}))
    tool = MCPBackedTool(NmapTool(), _spec(), client_factory=lambda: FakeMCPClient(result))
    out = tool.run_mcp(target="/src", intensity=Intensity.light, context={},
                       engagement_id="e1", run_id="r1")
    f = out.findings[0]
    assert f.title == "SQL Injection" and f.severity.value == "high"
    assert f.cwe == "CWE-89" and f.target == "/src/app.py"
    assert "tainted input" in f.evidence


def test_pooled_run_mcp_routes_through_the_pool():
    # When the spec is pooled, run_mcp must go through the injected pool (not spawn a client), and the
    # scope-checked target still flows to the server unchanged.
    class FakePool:
        def __init__(self):
            self.calls = []

        def call(self, spec, tool, arguments):
            self.calls.append((tool, dict(arguments)))
            return _text_result(json.dumps([{"name": "sqli", "severity": "high"}]))

    pool = FakePool()
    spec = MCPServerSpec.from_dict({
        "image": "eye-mcp-x:latest", "pooled": True, "tool": "snyk_code_scan", "target_arg": "path",
    })
    tool = MCPBackedTool(NmapTool(), spec, pool=pool)
    out = tool.run_mcp(target="/samples/app", intensity=Intensity.light, context={},
                       engagement_id="e1", run_id="r1")
    assert pool.calls == [("snyk_code_scan", {"path": "/samples/app"})]
    assert len(out.findings) == 1 and out.findings[0].severity.value == "high"


def test_target_and_intensity_argument_mapping():
    fake = FakeMCPClient(_text_result("ok"))
    tool = MCPBackedTool(NmapTool(), _spec(target_arg="path", intensity_arg="level",
                                           extra_args={"format": "json"}),
                         client_factory=lambda: fake)
    tool.run_mcp(target="/src", intensity=Intensity.aggressive, context={},
                 engagement_id="e1", run_id="r1")
    assert fake.calls[0][1] == {"path": "/src", "level": "aggressive", "format": "json"}
