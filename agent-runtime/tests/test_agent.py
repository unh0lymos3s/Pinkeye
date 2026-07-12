"""Phase 2 agent-loop tests with a scripted FakeProvider — no real model or network.

Key properties: the harness executes the model's tool choices, the scope guard still blocks an
out-of-scope target the *model* picked, and budgets stop the loop.
"""
from app.audit import EventType, MemoryAuditSink
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
