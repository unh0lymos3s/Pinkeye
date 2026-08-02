"""Round 6 — WS B: `_summarize` is the only thing the model ever sees from a tool run, and it used to
collapse two very different outcomes into one identical string: `0 services, 0 findings: no findings`
came out whether the tool genuinely scanned the target and found nothing, or whether it exited having
scanned nothing at all (confirmed in production for gitleaks, and true of six of seven sandboxed
tools this round — see round6-contract.md). These tests pin down the three-way split `_summarize` now
makes, plus the operator-facing `warning` event `_run_one` raises for the same condition.

`FakeStep` is a plain double, not the real `orchestrator.StepResult` — deliberately, so these tests
don't depend on WS-A's `exit_code`/`output_bytes`/`parsed_ok` fields landing on the real dataclass
first. `_summarize` reads those via `getattr(..., default)` for exactly this reason.
"""
from dataclasses import dataclass, field

from app.audit import MemoryAuditSink
from app.events import MemoryRunEventSink, RunEventKind
from app.models import Run
from runtime.agent import Budget, _summarize, run_agent
from runtime.llm.base import ProviderResponse, ToolCall
from runtime.llm.fake import FakeProvider
from runtime.registry import ToolRegistry
from runtime.tools.nmap import NmapTool

from tests.test_orchestrator import FakeGraph, FakeSandbox, make_engagement


@dataclass
class FakeStep:
    allowed: bool = True
    reason: str = ""
    services: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    note: str = ""
    error: str | None = None
    exit_code: int | None = None
    output_bytes: int = 0
    parsed_ok: bool = True


class _Finding:
    def __init__(self, title):
        self.title = title


# --- direct _summarize branch tests -----------------------------------------------------------

def test_denied_step_reads_as_denied():
    step = FakeStep(allowed=False, reason="out of scope")
    assert _summarize(step) == "DENIED by scope guard: out of scope. Choose a different in-scope target."


def test_error_step_reads_as_error():
    step = FakeStep(error="boom")
    assert _summarize(step) == "tool error: boom"


def test_knowledge_note_passes_through_even_with_zero_output_bytes():
    # A local/mcp knowledge tool has no sandbox exit code and (per the frozen WS-A contract) may
    # leave output_bytes at its zero default. The note branch must still win outright — a knowledge
    # tool answering "no known CVEs" must never get relabeled as a silent-zero failure.
    step = FakeStep(note="Known CVEs for foo: none found.", output_bytes=0, exit_code=None)
    assert _summarize(step) == "Known CVEs for foo: none found."


def test_zero_output_is_not_reported_as_clean():
    # THE regression this workstream exists to fix: allowed=True, no error, zero findings, zero
    # services and output_bytes=0 must not produce anything a model could read as "clean".
    step = FakeStep(output_bytes=0, exit_code=0)
    summary = _summarize(step)
    # Must not be (or contain) the string a genuinely clean scan produces — the message is allowed to
    # *mention* "no findings" only as part of explicitly warning against reporting it that way.
    assert summary != "0 services, 0 findings: no findings"
    assert "0 services, 0 findings:" not in summary
    assert "NOT" in summary  # "NOT a clean scan" / "must NOT be reported"
    assert "exit=0" in summary


def test_zero_output_message_notes_unknown_exit_code_when_absent():
    step = FakeStep(output_bytes=0, exit_code=None)
    assert "exit=unknown" in _summarize(step)


def test_denied_and_error_take_priority_over_zero_output():
    # Ordering matters: a denied or errored step must never fall through to the zero-output branch,
    # even though it also technically has output_bytes=0.
    denied = FakeStep(allowed=False, reason="x", output_bytes=0)
    assert "DENIED" in _summarize(denied)
    errored = FakeStep(error="crashed", output_bytes=0)
    assert "tool error" in _summarize(errored)


def test_unparsed_output_is_distinct_from_both_clean_and_silent():
    step = FakeStep(output_bytes=512, parsed_ok=False, exit_code=1)
    summary = _summarize(step)
    assert "UNPARSEABLE" in summary
    assert "512" in summary
    assert "exit=1" in summary
    assert "no findings" not in summary.lower()


def test_real_empty_scan_still_reads_as_clean():
    # Now trustworthy precisely because it can no longer be produced by the zero-output or
    # unparseable-output branches above.
    step = FakeStep(output_bytes=340, exit_code=0, parsed_ok=True)
    assert _summarize(step) == "0 services, 0 findings: no findings"


def test_real_findings_are_summarized_unchanged():
    step = FakeStep(output_bytes=340, exit_code=0, findings=[_Finding("SQLi"), _Finding("XSS")])
    assert _summarize(step) == "0 services, 2 findings: SQLi, XSS"


def test_summarize_tolerates_a_step_without_the_new_fields():
    # Simulates running before WS-A's StepResult change lands: no exit_code/output_bytes/parsed_ok
    # attributes at all. _summarize must not crash and must fall back to the pre-round-6 behavior
    # rather than misfiring the new branches on a step that never claimed to carry the new signal.
    class Bare:
        allowed = True
        reason = ""
        error = None
        note = ""
        services = []
        findings = []

    assert _summarize(Bare()) == "0 services, 0 findings: no findings"


# --- operator-facing warning, via the full run_agent loop -------------------------------------

def _one_nmap_call(engagement_target="10.0.0.5"):
    return FakeProvider([
        ProviderResponse(tool_calls=[ToolCall(id="c1", name="nmap",
                                              arguments={"target": engagement_target, "intensity": "light"})]),
        ProviderResponse(text="done"),
    ])


def test_warning_emitted_when_a_tool_produces_no_output(monkeypatch):
    eng = make_engagement()
    run = Run(id="rw1", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = _one_nmap_call()

    def fake_execute_tool_step(engagement, run, tool, target, intensity, sandbox, graph, audit, db,
                               context, memory):
        return FakeStep(output_bytes=0, exit_code=1)

    monkeypatch.setattr("runtime.agent.execute_tool_step", fake_execute_tool_step)

    run_agent(eng, run, provider, ToolRegistry([NmapTool()]), FakeSandbox(b""), graph, audit,
             budget=Budget(), events=sink)

    warnings = [e for e in sink.events
                if e.kind == RunEventKind.warning and e.data.get("scope") == "tool_output"]
    assert len(warnings) == 1
    w = warnings[0]
    assert w.data.get("tool") == "nmap"
    assert w.data.get("target") == "10.0.0.5"
    assert w.data.get("exit_code") == 1
    assert "nmap" in w.data.get("message", "")
    assert "NOT" in w.data.get("message", "")


def test_no_warning_emitted_for_a_healthy_step(monkeypatch):
    eng = make_engagement()
    run = Run(id="rw2", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = _one_nmap_call()

    def fake_execute_tool_step(engagement, run, tool, target, intensity, sandbox, graph, audit, db,
                               context, memory):
        return FakeStep(output_bytes=340, exit_code=0)

    monkeypatch.setattr("runtime.agent.execute_tool_step", fake_execute_tool_step)

    run_agent(eng, run, provider, ToolRegistry([NmapTool()]), FakeSandbox(b""), graph, audit,
             budget=Budget(), events=sink)

    assert not [e for e in sink.events if e.kind == RunEventKind.warning]


def test_no_warning_for_a_denied_step(monkeypatch):
    # A denied call also has no output_bytes worth speaking of, but it's not this workstream's
    # failure mode — the scope guard already tells the model plainly via the DENIED summary, and
    # raising a second, unrelated "no output" banner for every denial would just be noise.
    eng = make_engagement(cidr="10.0.0.0/24")
    run = Run(id="rw3", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([
        ProviderResponse(tool_calls=[ToolCall(id="c1", name="nmap",
                                              arguments={"target": "8.8.8.8", "intensity": "light"})]),
        ProviderResponse(text="done"),
    ])

    run_agent(eng, run, provider, ToolRegistry([NmapTool()]), FakeSandbox(b""), graph, audit,
             budget=Budget(), events=sink)

    assert not [e for e in sink.events if e.kind == RunEventKind.warning]
