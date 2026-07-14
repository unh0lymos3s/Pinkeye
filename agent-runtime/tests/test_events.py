"""Agent event-emission tests with a scripted FakeProvider + in-memory MemoryRunEventSink.

Properties asserted: events arrive in the right order (plan first, terminal status last); a scope
denial still emits a tool_finished the UI can show; a remembered map cannot widen scope; and the
raised budget still terminates a runaway loop.
"""
from app.audit import MemoryAuditSink
from app.events import MemoryRunEventSink, RunEventKind
from app.models import Run

from runtime.agent import Budget, _delta_events, run_agent
from runtime.llm.base import ProviderResponse, ToolCall
from runtime.llm.fake import FakeProvider
from runtime.registry import ToolRegistry
from runtime.tools.nmap import NmapTool

from tests.test_nmap_normalize import SAMPLE_XML
from tests.test_orchestrator import FakeGraph, FakeSandbox, make_engagement


def _registry():
    return ToolRegistry([NmapTool()])


def _call(target, cid="c1"):
    return ProviderResponse(text="scanning the host now",
                            tool_calls=[ToolCall(id=cid, name="nmap", arguments={"target": target})])


def test_bare_refusal_emits_refusal_event_not_silent_finish():
    # A model that only apologizes (no tool call) must be recorded as a refusal, not "agent finished".
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()
    provider = FakeProvider([ProviderResponse(text="I'm sorry, but I can't help with that request.")])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       FakeGraph(), MemoryAuditSink(), budget=Budget(), events=sink)

    assert result.stop_reason == "model refused"
    refusals = [e for e in sink.events if e.kind == RunEventKind.refusal]
    assert refusals and refusals[-1].data["stage"] == "final"


class _BoomProvider:
    """A provider whose LLM call fails, e.g. the model server is unreachable."""

    def complete(self, messages, tools):
        raise ConnectionError("connection refused")


def test_unreachable_llm_surfaces_error_and_failed_status():
    # The reported bug: a failed LLM call left the run stuck with no UI/log signal. Now it must emit
    # an `error` event and a terminal `failed` status instead of hanging silently.
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()

    result = run_agent(eng, run, _BoomProvider(), _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       FakeGraph(), MemoryAuditSink(), budget=Budget(), events=sink)

    assert result.stop_reason.startswith("llm error")
    kinds = [e.kind for e in sink.events]
    assert RunEventKind.error in kinds
    assert sink.events[-1].kind == RunEventKind.status
    assert sink.events[-1].data["status"] == "failed"


def test_events_emitted_in_expected_order():
    eng = make_engagement()  # allows 10.0.0.0/24
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()
    provider = FakeProvider([_call("10.0.0.5"), ProviderResponse(text="surface covered")])

    run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
              FakeGraph(), MemoryAuditSink(), budget=Budget(), events=sink)

    kinds = [e.kind for e in sink.events]
    assert kinds[0] == RunEventKind.plan          # plan is always first
    assert kinds[1] == RunEventKind.status         # then running status
    # tool lifecycle + reasoning + findings all present
    for expected in (RunEventKind.thinking, RunEventKind.tool_call, RunEventKind.tool_started,
                     RunEventKind.finding, RunEventKind.tool_finished):
        assert expected in kinds
    # terminal status is last and marks completion
    assert sink.events[-1].kind == RunEventKind.status
    assert sink.events[-1].data["status"] == "completed"
    # seq is strictly monotonic
    seqs = [e.seq for e in sink.events]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
    # plan event carries the effective budget so the UI progress bar reflects the real cap
    plan = sink.events[0]
    assert plan.data["budget"]["max_tool_calls"] == Budget().max_tool_calls


def test_denied_out_of_scope_call_still_emits_tool_finished():
    eng = make_engagement(cidr="10.0.0.0/24")
    run = Run(id="r2", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()
    provider = FakeProvider([_call("8.8.8.8"), ProviderResponse(text="stopping")])

    run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
              FakeGraph(), MemoryAuditSink(), budget=Budget(), events=sink)

    finished = [e for e in sink.events if e.kind == RunEventKind.tool_finished]
    assert finished and finished[0].data.get("denied") is True
    assert "DENIED" in finished[0].data.get("summary", "")


class _StubMemory:
    """A remembered map that lists an out-of-scope host, to prove memory is guidance only."""

    def snapshot(self, engagement_id):
        return {"devices": [{"address": "8.8.8.8", "status": "active",
                             "services": [{"port": 53, "proto": "udp", "service": "dns"}]}]}

    def observe(self, *args, **kwargs):
        return None


def test_remembered_map_cannot_widen_scope():
    eng = make_engagement(cidr="10.0.0.0/24")
    run = Run(id="r3", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    # The map names 8.8.8.8; the model takes the bait and targets it. The guard must still deny.
    provider = FakeProvider([_call("8.8.8.8"), ProviderResponse(text="stopping")])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget(), events=sink, memory=_StubMemory())

    assert result.findings == 0 and graph.findings == []
    finished = [e for e in sink.events if e.kind == RunEventKind.tool_finished]
    assert finished and finished[0].data.get("denied") is True


def test_raised_budget_still_terminates_runaway_loop():
    eng = make_engagement()
    run = Run(id="r4", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    # Model asks for a tool forever; the default (raised) budget must still stop it.
    provider = FakeProvider([_call("10.0.0.5", cid=f"c{i}") for i in range(1000)])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget())

    assert result.tool_calls_used == Budget().max_tool_calls
    assert result.stop_reason == "tool-call budget reached"


def test_delta_event_entity_kind_does_not_collide_with_event_kind():
    # Regression: a memory entity carries its own `kind` (host/service/...). Splatting it into
    # emit("memory_delta", **entry) once raised "got multiple values for argument 'kind'" and crashed
    # the whole run. The entity kind must be preserved under a non-colliding key.
    events = _delta_events({
        "added": [{"key": "10.0.0.5", "kind": "host", "label": "10.0.0.5"}],
        "newly_exploitable": [{"key": "10.0.0.5:22", "kind": "service"}],
    })
    assert all("kind" not in e for e in events)              # no bare `kind` to collide
    assert events[0]["entity_kind"] == "host" and events[0]["change"] == "added"
    assert events[1]["entity_kind"] == "service" and events[1]["change"] == "newly_exploitable"
    # And the payloads splat cleanly into an emit-shaped call (kind is positional).
    def emit(kind, **data):
        return kind, data
    for e in events:
        assert emit("memory_delta", **e)[0] == "memory_delta"
