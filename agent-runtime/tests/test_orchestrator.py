"""End-to-end orchestrator test with fake sandbox/graph, proving the guard->audit->graph spine."""
from datetime import datetime, timedelta, timezone

from app.audit import EventType, MemoryAuditSink, hash_output
from app.models import Engagement, Intensity, Run, RunStatus, Scope
from app.scope import sign_scope
from runtime.orchestrator import execute_tool_step, run_scan
from runtime.sandbox import SandboxResult
from runtime.tools.base import ToolOutput
from runtime.tools.nmap import NmapTool
from tests.test_nmap_normalize import SAMPLE_XML


class FakeSandbox:
    """Returns canned output instead of launching a container.

    Round 6 — WS A: extended (in a backward-compatible way — `FakeSandbox(stdout)` still works
    unchanged, which is why test_abort.py and test_subagents.py, which import this class, are
    untouched) to also capture every call's kwargs, so a test can assert that tmpfs/artifact_path/
    mem_limit/timeout_seconds actually reach `sandbox.run`, and to optionally hand back an artifact +
    a non-zero exit code, so the same fake covers both the plain-stdout tools and the
    artifact-extraction tools without a second fake class."""

    def __init__(self, stdout: bytes, exit_code: int = 0, artifact: bytes | None = None,
                 artifact_missing: bool = False):
        self._stdout = stdout
        self._exit_code = exit_code
        self._artifact = artifact
        self._artifact_missing = artifact_missing
        self.calls: list[dict] = []

    def run(self, image, command, source_dir=None, egress=None, **kwargs):
        self.calls.append({"image": image, "command": command, "source_dir": source_dir,
                           "egress": egress, **kwargs})
        return SandboxResult(exit_code=self._exit_code, stdout=self._stdout, stderr=b"",
                             artifact=self._artifact, artifact_missing=self._artifact_missing)


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


class _Cancels:
    """Stand-in for the control-plane's RunCancels registry: only `is_cancelled` is what run_scan
    consults, so the test doesn't need the real bounded-retention implementation."""

    def __init__(self, cancelled: set[str] | None = None):
        self._cancelled = cancelled or set()

    def is_cancelled(self, run_id: str) -> bool:
        return run_id in self._cancelled


def test_aborted_scan_reports_aborted_not_completed():
    # An abort kills the container mid-step, so the step itself may look like anything from a clean
    # parse to an error. Whatever it looks like, the operator pressed stop — the run must say so.
    eng = make_engagement()
    run = Run(id="r5", engagement_id="e1", target="10.0.0.5")
    audit = MemoryAuditSink()

    result = run_scan(eng, run, NmapTool(), Intensity.light,
                      FakeSandbox(SAMPLE_XML.encode()), FakeGraph(), audit,
                      cancels=_Cancels({"r5"}))

    assert result.status == RunStatus.aborted
    assert any(e.type == EventType.run_status and "aborted" in (e.detail or "") for e in audit.events)


def test_uncancelled_scan_is_unaffected_by_the_registry():
    # The cancel check must not perturb the ordinary path: a registry that holds some *other* run's
    # id has to leave this one completing exactly as it did before abort existed.
    eng = make_engagement()
    run = Run(id="r6", engagement_id="e1", target="10.0.0.5")
    graph = FakeGraph()

    result = run_scan(eng, run, NmapTool(), Intensity.light,
                      FakeSandbox(SAMPLE_XML.encode()), graph, MemoryAuditSink(),
                      cancels=_Cancels({"some-other-run"}))

    assert result.status == RunStatus.completed
    assert len(graph.services) == 2 and len(graph.findings) == 2


# ==== Round 6 — WS A: StepResult signals, tmpfs/artifact/override plumbing =========================
#
# Three fake tools stand in for the "declares an optional sandbox attribute" shapes C/D's real tools
# take, without depending on their files at all (sast.py/dast.py are owned by other workstreams):
#   - _ExplodingParseTool: a tool whose parse() blows up on the bytes it's handed — the "hostile or
#     malformed report" case parsed_ok exists for.
#   - _ArtifactTool: declares artifact_path, the gitleaks/ZAP shape — parse() must see the artifact,
#     not stdout.
#   - _ResourceHeavyTool: declares tmpfs/mem_limit/timeout_seconds, the ZAP-needs-more-than-default
#     shape — sandbox.run() must receive all three.

class _ExplodingParseTool:
    name = "exploding"
    description = "test tool whose parser cannot read its own tool's output"
    image = "test-image"

    def build_command(self, target, intensity):
        return ["scan", target]

    def parse(self, raw, *, engagement_id, run_id, target):
        raise ValueError(f"not valid JSON: {raw!r}")


class _ArtifactTool:
    name = "artifact-only"
    description = "test tool that can only write its report to a file, like gitleaks/ZAP"
    image = "test-image"
    artifact_path = "/report.json"

    def build_command(self, target, intensity):
        return ["detect", "--report-path", "/report.json"]

    def parse(self, raw, *, engagement_id, run_id, target):
        import json
        items = json.loads(raw)
        return ToolOutput(note=f"parsed {len(items)} item(s) from the artifact")


class _ResourceHeavyTool:
    name = "resource-heavy"
    description = "test tool with per-tool sandbox overrides, like ZAP"
    image = "test-image"
    tmpfs = ["/zap/wrk"]
    mem_limit = "2g"
    timeout_seconds = 900

    def build_command(self, target, intensity):
        return ["scan", target]

    def parse(self, raw, *, engagement_id, run_id, target):
        return ToolOutput()


def test_step_result_reports_exit_code_and_output_bytes():
    eng = make_engagement()
    run = Run(id="r7", engagement_id="e1", target="10.0.0.5")

    step = execute_tool_step(eng, run, NmapTool(), "10.0.0.5", Intensity.light,
                             FakeSandbox(SAMPLE_XML.encode()), FakeGraph(), MemoryAuditSink())

    assert step.exit_code == 0
    assert step.output_bytes == len(SAMPLE_XML.encode())
    assert step.parsed_ok is True


def test_empty_output_is_visible_as_zero_bytes_not_hidden():
    # This is the whole point of round 6: a tool that exits clean with nothing to show for it must
    # leave a trace distinguishable from "scanned and found nothing," not silently look identical to
    # a clean, complete scan the way it did before these fields existed.
    eng = make_engagement()
    run = Run(id="r8", engagement_id="e1", target="10.0.0.5")

    step = execute_tool_step(eng, run, NmapTool(), "10.0.0.5", Intensity.light,
                             FakeSandbox(b""), FakeGraph(), MemoryAuditSink())

    assert step.exit_code == 0
    assert step.output_bytes == 0
    assert step.allowed is True and step.error is None


def test_parse_failure_is_distinguished_from_sandbox_failure():
    eng = make_engagement()
    run = Run(id="r9", engagement_id="e1", target="10.0.0.5")

    step = execute_tool_step(eng, run, _ExplodingParseTool(), "10.0.0.5", Intensity.light,
                             FakeSandbox(b"garbage, not json"), FakeGraph(), MemoryAuditSink())

    # The tool ran (exit 0, non-empty payload) but the parser choked on it: parsed_ok says so, and
    # crucially this is NOT the same path as a sandbox-level failure — `error` stays unset and the
    # step is still `allowed`, so it doesn't get mistaken for "the run failed."
    assert step.allowed is True
    assert step.error is None
    assert step.exit_code == 0
    assert step.output_bytes == len(b"garbage, not json")
    assert step.parsed_ok is False
    assert step.findings == [] and step.services == []


def test_sandbox_level_failure_still_uses_the_error_path():
    # Contrast with the previous test: an exception from sandbox.run() itself (not from parse()) is a
    # genuinely different failure and must keep going through the original `error` branch.
    class _ExplodingSandbox:
        def run(self, *args, **kwargs):
            raise RuntimeError("docker daemon unreachable")

    eng = make_engagement()
    run = Run(id="r10", engagement_id="e1", target="10.0.0.5")

    step = execute_tool_step(eng, run, NmapTool(), "10.0.0.5", Intensity.light,
                             _ExplodingSandbox(), FakeGraph(), MemoryAuditSink())

    assert step.allowed is True
    assert step.error and "docker daemon unreachable" in step.error


def test_artifact_path_tool_is_parsed_from_the_artifact_not_stdout():
    eng = make_engagement()
    run = Run(id="r11", engagement_id="e1", target="10.0.0.5")
    audit = MemoryAuditSink()
    artifact_bytes = b'[{"a": 1}, {"b": 2}]'
    # exit_code=1 mirrors gitleaks: a nonzero exit when it found something, artifact still valid.
    sandbox = FakeSandbox(stdout=b"", exit_code=1, artifact=artifact_bytes)

    step = execute_tool_step(eng, run, _ArtifactTool(), "10.0.0.5", Intensity.light,
                             sandbox, FakeGraph(), audit)

    assert step.allowed is True and step.error is None
    assert step.exit_code == 1
    assert step.output_bytes == len(artifact_bytes)
    assert step.note == "parsed 2 item(s) from the artifact"
    # The audit hash is of the artifact — the thing actually parsed — not the (empty) stdout, since
    # that hash is the replay record of what execute_tool_step really handed to tool.parse().
    finished = [e for e in audit.events if e.type == EventType.tool_finished]
    assert finished[-1].output_sha256 == hash_output(artifact_bytes)


def test_artifact_missing_is_audited_and_parsed_from_empty_bytes():
    eng = make_engagement()
    run = Run(id="r12", engagement_id="e1", target="10.0.0.5")
    audit = MemoryAuditSink()
    sandbox = FakeSandbox(stdout=b"", exit_code=0, artifact=None, artifact_missing=True)

    step = execute_tool_step(eng, run, _ArtifactTool(), "10.0.0.5", Intensity.light,
                             sandbox, FakeGraph(), audit)

    assert step.output_bytes == 0
    finished = [e for e in audit.events if e.type == EventType.tool_finished]
    assert "artifact missing" in (finished[-1].detail or "")


def test_tool_declared_tmpfs_and_resource_overrides_reach_sandbox_run():
    eng = make_engagement()
    run = Run(id="r13", engagement_id="e1", target="10.0.0.5")
    sandbox = FakeSandbox(b"")

    execute_tool_step(eng, run, _ResourceHeavyTool(), "10.0.0.5", Intensity.light,
                      sandbox, FakeGraph(), MemoryAuditSink())

    call = sandbox.calls[0]
    assert call["tmpfs"] == ["/zap/wrk"]
    assert call["mem_limit"] == "2g"
    assert call["timeout_seconds"] == 900
    assert call["artifact_path"] is None


def test_tool_without_optional_attributes_passes_none_for_all_of_them():
    # nmap (and every other existing tool) declares none of tmpfs/artifact_path/mem_limit/
    # timeout_seconds — this proves getattr(..., None) is really what reaches sandbox.run for them,
    # i.e. their container config is byte-for-byte what it was before this round.
    eng = make_engagement()
    run = Run(id="r14", engagement_id="e1", target="10.0.0.5")
    sandbox = FakeSandbox(SAMPLE_XML.encode())

    execute_tool_step(eng, run, NmapTool(), "10.0.0.5", Intensity.light,
                      sandbox, FakeGraph(), MemoryAuditSink())

    call = sandbox.calls[0]
    assert call["tmpfs"] is None
    assert call["artifact_path"] is None
    assert call["mem_limit"] is None
    assert call["timeout_seconds"] is None


# ---- local/mcp tools: no sandbox exit code, and a note-only result must not look like "no output" --

class _FakeLocalTool:
    name = "cve-ish"
    description = "test knowledge tool"
    surface = "knowledge"
    local = True

    def __init__(self, note: str = "No known CVEs found for widget."):
        self._note = note

    def run_local(self, *, target, intensity, context, engagement_id, run_id):
        return ToolOutput(note=self._note)


def test_local_tool_has_no_exit_code_and_nonzero_output_bytes():
    eng = make_engagement()
    run = Run(id="r15", engagement_id="e1", target="10.0.0.5")

    step = execute_tool_step(eng, run, _FakeLocalTool(), "10.0.0.5", Intensity.light,
                             sandbox=None, graph=FakeGraph(), audit=MemoryAuditSink())

    assert step.exit_code is None
    assert step.output_bytes == len("No known CVEs found for widget.".encode("utf-8"))
    assert step.parsed_ok is True


def test_local_tool_with_no_note_still_reports_nonzero_output_bytes():
    # A local tool that legitimately has nothing to say (empty note, no findings) must still not read
    # as "produced zero output" to whatever layer above is watching for that — that's the one failure
    # mode this round exists to fix, and a knowledge tool's silence is not that failure mode.
    eng = make_engagement()
    run = Run(id="r16", engagement_id="e1", target="10.0.0.5")

    step = execute_tool_step(eng, run, _FakeLocalTool(note=""), "10.0.0.5", Intensity.light,
                             sandbox=None, graph=FakeGraph(), audit=MemoryAuditSink())

    assert step.exit_code is None
    assert step.output_bytes > 0


class _FakeMcpSpec:
    command = "test-cmd"
    tool = "scan"


class _FakeMcpTool:
    name = "mcp-ish"
    description = "test mcp-backed tool"
    image = "unused"
    mcp = _FakeMcpSpec()

    def run_mcp(self, *, target, intensity, context, engagement_id, run_id):
        return ToolOutput(note="mcp server said hi")


def test_mcp_tool_has_no_exit_code_and_nonzero_output_bytes():
    eng = make_engagement()
    run = Run(id="r17", engagement_id="e1", target="10.0.0.5")
    audit = MemoryAuditSink()

    step = execute_tool_step(eng, run, _FakeMcpTool(), "10.0.0.5", Intensity.light,
                             sandbox=None, graph=FakeGraph(), audit=audit)

    assert step.exit_code is None
    assert step.output_bytes == len("mcp server said hi".encode("utf-8"))
    finished = [e for e in audit.events if e.type == EventType.tool_finished]
    assert "mcp[test-cmd:scan]" in (finished[-1].detail or "")
