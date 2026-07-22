"""End-to-end orchestrator test with fake sandbox/graph, proving the guard->audit->graph spine."""
from datetime import datetime, timedelta, timezone

from app.audit import EventType, MemoryAuditSink
from app.models import Engagement, Intensity, Run, RunStatus, Scope
from app.scope import sign_scope
from runtime.orchestrator import run_scan
from runtime.sandbox import SandboxResult
from runtime.tools.nmap import NmapTool
from tests.test_nmap_normalize import SAMPLE_XML


class FakeSandbox:
    """Returns canned nmap XML instead of launching a container."""

    def __init__(self, stdout: bytes):
        self._stdout = stdout

    def run(self, image, command, **kwargs):
        # Accept any sandbox kwargs (source_dir, egress, ...) so tests survive signature growth.
        return SandboxResult(exit_code=0, stdout=self._stdout, stderr=b"")


class FakeGraph:
    def __init__(self):
        self.services = []
        self.findings = []

    def upsert_service(self, *args):
        self.services.append(args)

    def record_finding(self, finding):
        self.findings.append(finding)


def make_engagement(cidr="10.0.0.0/24") -> Engagement:
    now = datetime.now(timezone.utc)
    scope = Scope(
        allowed_cidrs=[cidr],
        allowed_domains=[],
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
        max_intensity=Intensity.normal,
    )
    scope.signature = sign_scope(scope)
    return Engagement(id="e1", name="test", scope=scope)


def test_in_scope_run_writes_graph_and_completes():
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    graph = FakeGraph()
    audit = MemoryAuditSink()

    result = run_scan(eng, run, NmapTool(), Intensity.light,
                      FakeSandbox(SAMPLE_XML.encode()), graph, audit)

    assert result.status == RunStatus.completed
    assert len(graph.services) == 2 and len(graph.findings) == 2
    # The raw output was hashed and audited for replay.
    assert any(e.type == EventType.tool_finished and e.output_sha256 for e in audit.events)


def test_out_of_scope_run_is_rejected_before_tool_runs():
    eng = make_engagement(cidr="192.168.0.0/24")  # target 10.0.0.5 is now out of scope
    run = Run(id="r2", engagement_id="e1", target="10.0.0.5")
    graph = FakeGraph()
    audit = MemoryAuditSink()

    result = run_scan(eng, run, NmapTool(), Intensity.light,
                      FakeSandbox(SAMPLE_XML.encode()), graph, audit)

    assert result.status == RunStatus.rejected
    assert graph.findings == []  # nothing was scanned or written
    assert any(e.type == EventType.scope_decision and e.allowed is False for e in audit.events)


class RecordingMemory:
    """Captures observe() calls so we can assert single-tool scans feed the cross-run map too."""

    def __init__(self):
        self.calls = []

    def observe(self, engagement_id, run_id, services, findings):
        self.calls.append((engagement_id, run_id, list(services), list(findings)))
        return None


def test_in_scope_scan_feeds_network_memory():
    eng = make_engagement()
    run = Run(id="r3", engagement_id="e1", target="10.0.0.5")
    memory = RecordingMemory()

    run_scan(eng, run, NmapTool(), Intensity.light,
             FakeSandbox(SAMPLE_XML.encode()), FakeGraph(), MemoryAuditSink(), memory=memory)

    assert len(memory.calls) == 1
    engagement_id, run_id, services, findings = memory.calls[0]
    assert engagement_id == "e1" and run_id == "r3"
    assert services and findings  # the scan's observations were handed to the memory engine


def test_rejected_scan_does_not_touch_memory():
    eng = make_engagement(cidr="192.168.0.0/24")  # 10.0.0.5 is out of scope
    run = Run(id="r4", engagement_id="e1", target="10.0.0.5")
    memory = RecordingMemory()

    run_scan(eng, run, NmapTool(), Intensity.light,
             FakeSandbox(SAMPLE_XML.encode()), FakeGraph(), MemoryAuditSink(), memory=memory)

    assert memory.calls == []  # denied before execution, so nothing is observed
