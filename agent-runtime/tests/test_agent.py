"""Phase 2 agent-loop tests with a scripted FakeProvider — no real model or network.

Key properties: the harness executes the model's tool choices, the scope guard still blocks an
out-of-scope target the *model* picked, and budgets stop the loop.
"""
from app.audit import EventType, MemoryAuditSink
from app.events import MemoryRunEventSink, RunEventKind
from app.models import Intensity
from runtime.agent import Budget, run_agent
from runtime.llm.base import ProviderResponse, ToolCall
from runtime.llm.fake import FakeProvider
from runtime.registry import ToolRegistry
from runtime.tools.nmap import NmapTool

from tests.test_nmap_normalize import SAMPLE_XML
from tests.test_orchestrator import FakeGraph, FakeSandbox, make_engagement


def _registry():
    return ToolRegistry([NmapTool()])


def _call(target, intensity="light", cid="c1"):
    return ProviderResponse(tool_calls=[ToolCall(id=cid, name="nmap", arguments={"target": target, "intensity": intensity})])


def test_agent_runs_model_chosen_tool_and_persists():
    eng = make_engagement()  # allows 10.0.0.0/24
    from app.models import Run

    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    # Model asks to scan the in-scope host, then returns a final text answer (no tool call).
    provider = FakeProvider([_call("10.0.0.5"), ProviderResponse(text="surface covered")])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget())

    assert result.tool_calls_used == 1
    assert result.findings == 2 and len(graph.findings) == 2
    assert result.stop_reason == "agent finished"


def test_agent_cannot_widen_scope():
    eng = make_engagement(cidr="10.0.0.0/24")
    from app.models import Run

    run = Run(id="r2", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    # The model tries an out-of-scope host; the guard must deny and nothing gets scanned.
    provider = FakeProvider([_call("8.8.8.8"), ProviderResponse(text="ok, stopping")])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget())

    assert result.findings == 0 and graph.findings == []
    assert any(e.type == EventType.scope_decision and e.allowed is False for e in audit.events)
    # The denial was fed back to the model as a tool result it could react to.
    tool_msgs = [m for c in provider.calls for m in c if m.role == "tool"]
    assert any("DENIED" in m.content for m in tool_msgs)


def test_budget_caps_tool_calls():
    eng = make_engagement()
    from app.models import Run

    run = Run(id="r3", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    # Model keeps asking for tools forever; the budget must stop it at 2 calls.
    provider = FakeProvider([_call("10.0.0.5", cid=f"c{i}") for i in range(10)])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget(max_tool_calls=2))

    assert result.tool_calls_used == 2
    assert result.stop_reason == "tool-call budget reached"


# --- B2: repeat-call guard. Re-running the identical (tool, target, intensity) triple must not
# re-touch the sandbox or re-persist results, but must still cost a slot in the tool-call budget.
def test_repeat_call_is_denied_without_rerunning_the_tool():
    eng = make_engagement()
    from app.models import Run

    run = Run(id="r4", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    # The model asks for the exact same scan twice, then stops.
    provider = FakeProvider([
        _call("10.0.0.5", cid="c1"),
        _call("10.0.0.5", cid="c2"),
        ProviderResponse(text="done"),
    ])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget())

    # Both calls still count against the budget...
    assert result.tool_calls_used == 2
    # ...but only the first one actually ran: the sandbox/graph only saw it once.
    assert len(graph.findings) == 2
    assert sum(1 for e in audit.events if e.type == EventType.tool_started) == 1
    # The model was told plainly that the second call was a no-op repeat, not silently dropped.
    tool_msgs = [m for c in provider.calls for m in c if m.role == "tool"]
    assert any("already ran nmap on 10.0.0.5 this run" in m.content for m in tool_msgs)


def test_repeat_call_guard_is_per_run_not_global():
    # A different intensity is a different call and must run normally; likewise a fresh run_agent
    # invocation (e.g. a new run) must not remember another run's calls.
    eng = make_engagement()
    from app.models import Run

    run = Run(id="r5", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    provider = FakeProvider([
        _call("10.0.0.5", intensity="light", cid="c1"),
        _call("10.0.0.5", intensity="normal", cid="c2"),
        ProviderResponse(text="done"),
    ])

    result = run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
                       graph, audit, budget=Budget())

    assert result.tool_calls_used == 2
    assert len(graph.findings) == 4  # both calls actually ran -> persisted twice
    assert sum(1 for e in audit.events if e.type == EventType.tool_started) == 2


def test_repeat_call_emits_tool_finished_with_repeat_flag():
    eng = make_engagement()
    from app.models import Run

    run = Run(id="r6", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([
        _call("10.0.0.5", cid="c1"),
        _call("10.0.0.5", cid="c2"),
        ProviderResponse(text="done"),
    ])

    run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()),
             graph, audit, budget=Budget(), events=sink)

    repeats = [e for e in sink.events
              if e.kind == RunEventKind.tool_finished and e.data.get("repeat")]
    assert len(repeats) == 1


# --- B2: seed-range guidance. A range seed target gets an extra system message telling the model to
# sweep once instead of iterating addresses.
def test_range_seed_gets_guidance_message():
    eng = make_engagement(cidr="10.0.0.0/24")
    from app.models import Run

    run = Run(id="r7", engagement_id="e1", target="10.0.0.0/24")
    graph, audit = FakeGraph(), MemoryAuditSink()
    provider = FakeProvider([ProviderResponse(text="no action")])

    run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()), graph, audit,
             budget=Budget())

    system_msgs = [m.content for c in provider.calls for m in c if m.role == "system"]
    assert any("range of 256 addresses" in s for s in system_msgs)
    assert any("ONE host-discovery sweep" in s for s in system_msgs)


def test_single_host_seed_gets_no_range_guidance():
    eng = make_engagement()
    from app.models import Run

    run = Run(id="r8", engagement_id="e1", target="10.0.0.5")
    graph, audit = FakeGraph(), MemoryAuditSink()
    provider = FakeProvider([ProviderResponse(text="no action")])

    run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()), graph, audit,
             budget=Budget())

    system_msgs = [m.content for c in provider.calls for m in c if m.role == "system"]
    assert not any("host-discovery sweep" in s for s in system_msgs)


# --- B3: the scope-guard-disabled warning is emitted once, right after `plan`, only when the guard
# is off for this engagement.
def test_scope_guard_disabled_emits_a_warning_event_after_plan():
    eng = make_engagement()
    eng.scope.scope_guard_enabled = False
    from app.scope import sign_scope

    eng.scope.signature = sign_scope(eng.scope)
    from app.models import Run

    run = Run(id="r9", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([ProviderResponse(text="no action")])

    run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()), graph, audit,
             budget=Budget(), events=sink)

    kinds = [e.kind for e in sink.events]
    assert RunEventKind.warning in kinds
    plan_idx = kinds.index(RunEventKind.plan)
    warning_idx = kinds.index(RunEventKind.warning)
    assert warning_idx == plan_idx + 1
    warning = sink.events[warning_idx]
    assert warning.data.get("scope") == "scope_guard"
    assert "DISABLED" in warning.data.get("message", "")


def test_scope_guard_enabled_emits_no_warning_event():
    eng = make_engagement()  # scope_guard_enabled defaults True
    from app.models import Run

    run = Run(id="r10", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([ProviderResponse(text="no action")])

    run_agent(eng, run, provider, _registry(), FakeSandbox(SAMPLE_XML.encode()), graph, audit,
             budget=Budget(), events=sink)

    assert RunEventKind.warning not in [e.kind for e in sink.events]
