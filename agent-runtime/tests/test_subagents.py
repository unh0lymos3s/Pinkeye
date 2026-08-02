"""Specialist sub-agent tests with a scripted FakeProvider — no real model, network, or containers.

Because the orchestrator and its nested specialists share one FakeProvider, the script is the whole
tree in call order: first the orchestrator's dispatch, then the child's tool call(s), then the child's
final message, then the orchestrator's final message.

Specialists are dispatched by persona id (Scout/Viper/Warden/Oracle/Reaper/Ghost — see
runtime/personas.py and agents.toml), not by the old stage-shaped names (recon/dast/sast/...): those
now live only as aliases resolved at the API boundary (`personas.resolve`), never as something the
orchestrator model calls directly.

Properties asserted: the orchestrator delegates to a specialist that actually runs its persona's
tool; the child's budget usage folds back into the parent; the scope guard still denies an
out-of-scope target a child picked; gated specialists are only offered when the scope authorizes
them; a nested child suppresses run-level plan/status lifecycle and tags its events with the
specialist; and a single-specialist profile runs directly over a persona-narrowed registry.
"""
from datetime import datetime, timedelta, timezone

from app.audit import EventType, MemoryAuditSink
from app.events import MemoryRunEventSink, RunEventKind
from app.models import Engagement, Intensity, Run, Scope
from app.scope import sign_scope

from runtime.agent import Budget, run_agent
from runtime.llm.base import ProviderResponse, ToolCall
from runtime.llm.fake import FakeProvider
from runtime.pipeline import tools_for_stage
from runtime.registry import ToolRegistry
from runtime.subagents import specialist_registry, specialist_specs
from runtime.tools.nmap import NmapTool

from tests.test_nmap_normalize import SAMPLE_XML
from tests.test_orchestrator import FakeGraph, FakeSandbox


def make_engagement(cidr="10.0.0.0/24", exploit=False, creds=False) -> Engagement:
    now = datetime.now(timezone.utc)
    scope = Scope(
        allowed_cidrs=[cidr],
        allowed_domains=[],
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
        max_intensity=Intensity.normal,
        allow_exploit=exploit,
        allow_credential_attacks=creds,
    )
    scope.signature = sign_scope(scope)
    return Engagement(id="e1", name="test", scope=scope)


def _dispatch(persona_id, target, cid="o1"):
    return ProviderResponse(tool_calls=[ToolCall(id=cid, name=persona_id, arguments={"target": target})])


def _nmap(target, cid="c1"):
    return ProviderResponse(tool_calls=[ToolCall(id=cid, name="nmap", arguments={"target": target})])


def _sandbox():
    return FakeSandbox(SAMPLE_XML.encode())


# ---- stage <-> tool mapping (pipeline rail metadata, independent of personas) --------------------

def test_tools_for_stage_matches_pipeline():
    assert set(tools_for_stage("static scan")) == {"semgrep", "gitleaks", "trivy"}
    assert tools_for_stage("recon") == ["nmap"]
    assert tools_for_stage("report") == []  # a presentation-only stage owns no tool


# ---- specialist offering / gating ---------------------------------------------------------------

def test_specialist_specs_hides_gated_without_flags():
    names = {s.name for s in specialist_specs(make_engagement().scope)}
    assert {"scout", "viper", "warden", "oracle"} <= names
    assert "reaper" not in names and "ghost" not in names


def test_specialist_specs_offers_gated_with_flags():
    names = {s.name for s in specialist_specs(make_engagement(exploit=True, creds=True).scope)}
    assert "reaper" in names and "ghost" in names


def test_specialist_registry_does_not_inherit_other_stages_tools():
    # Warden (static scan) over a pool that only has nmap must get an EMPTY registry, never nmap.
    reg = specialist_registry("warden", [NmapTool()])
    assert reg.get("nmap") is None
    # Scout (recon) over the same pool gets exactly nmap.
    assert specialist_registry("scout", [NmapTool()]).get("nmap") is not None


# ---- orchestrator delegation --------------------------------------------------------------------

def test_orchestrator_delegates_and_child_runs_the_stage_tool():
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([
        _dispatch("scout", "10.0.0.5"),         # orchestrator: delegate to Scout
        _nmap("10.0.0.5"),                      # child: run nmap in its own context
        ProviderResponse(text="recon done"),    # child: finish
        ProviderResponse(text="assessment done"),  # orchestrator: finish
    ])

    result = run_agent(eng, run, provider, ToolRegistry([]), _sandbox(), graph, audit,
                       budget=Budget(), events=sink, specialist_pool=[NmapTool()])

    # The child actually scanned via the shared spine.
    assert len(graph.findings) == 2 and result.findings == 2
    # Lifecycle events for the delegation are present.
    kinds = [e.kind for e in sink.events]
    assert RunEventKind.subagent_started in kinds and RunEventKind.subagent_finished in kinds
    # The child's own events are tagged so the UI can group them under the specialist.
    assert [e for e in sink.events if e.data.get("subagent") == "scout"]
    # Exactly one run-level plan and one terminal completed status — the child suppresses both.
    assert sum(1 for e in sink.events if e.kind == RunEventKind.plan) == 1
    completed = [e for e in sink.events
                 if e.kind == RunEventKind.status and e.data.get("status") == "completed"]
    assert len(completed) == 1


def test_specialist_usage_folds_into_parent_budget():
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    provider = FakeProvider([
        _dispatch("scout", "10.0.0.5"),
        _nmap("10.0.0.5"),
        ProviderResponse(text="recon done"),
        ProviderResponse(text="done"),
    ])

    result = run_agent(eng, run, provider, ToolRegistry([]), _sandbox(), FakeGraph(),
                       MemoryAuditSink(), budget=Budget(), specialist_pool=[NmapTool()])

    # 1 child nmap call + 1 orchestrator dispatch = 2 tool calls folded into the parent budget.
    assert result.tool_calls_used == 2


def test_subagent_events_carry_the_persona_identity():
    # The transcript renders a delegated pass as the persona itself ("🛰 Scout"), so the id, label and
    # glyph have to reach the event stream — the UI has no other source for them mid-run.
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()
    provider = FakeProvider([
        _dispatch("scout", "10.0.0.5"),
        _nmap("10.0.0.5"),
        ProviderResponse(text="recon done"),
        ProviderResponse(text="done"),
    ])

    run_agent(eng, run, provider, ToolRegistry([]), _sandbox(), FakeGraph(), MemoryAuditSink(),
              budget=Budget(), events=sink, specialist_pool=[NmapTool()])

    for kind in (RunEventKind.subagent_started, RunEventKind.subagent_finished):
        event = next(e for e in sink.events if e.kind == kind)
        assert event.data["persona"] == "scout"
        assert event.data["persona_label"] == "Scout"
        assert event.data["glyph"]
        # The legacy fields stay put: the UI falls back to them for an unknown persona.
        assert event.data["specialist"] == "scout" and event.data["stage"] == "recon"


def test_plan_event_carries_the_launched_persona():
    # The picker's selection is client-side state that resets on reload, so the plan event is what
    # lets a reconnecting operator see which persona the in-flight run actually belongs to.
    from runtime.personas import resolve

    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()

    run_agent(eng, run, FakeProvider([ProviderResponse(text="done")]), ToolRegistry([NmapTool()]),
              _sandbox(), FakeGraph(), MemoryAuditSink(), budget=Budget(), events=sink,
              persona=resolve("reaper"))

    plan = next(e for e in sink.events if e.kind == RunEventKind.plan)
    assert plan.data["persona"] == "reaper" and plan.data["persona_label"] == "Reaper"


def test_plan_event_omits_persona_fields_when_none_was_passed():
    # A run launched without a persona must not emit placeholder identity — the UI distinguishes
    # "no persona" from "a persona with no label", and only the former falls back to the old rendering.
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    sink = MemoryRunEventSink()

    run_agent(eng, run, FakeProvider([ProviderResponse(text="done")]), ToolRegistry([NmapTool()]),
              _sandbox(), FakeGraph(), MemoryAuditSink(), budget=Budget(), events=sink)

    plan = next(e for e in sink.events if e.kind == RunEventKind.plan)
    assert "persona" not in plan.data and "glyph" not in plan.data


def test_child_scope_denial_still_enforced_and_surfaced():
    eng = make_engagement(cidr="10.0.0.0/24")
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    graph, audit, sink = FakeGraph(), MemoryAuditSink(), MemoryRunEventSink()
    provider = FakeProvider([
        _dispatch("scout", "8.8.8.8"),          # orchestrator delegates against an out-of-scope host
        _nmap("8.8.8.8"),                       # child tries to scan it
        ProviderResponse(text="was denied"),    # child finish
        ProviderResponse(text="done"),          # orchestrator finish
    ])

    result = run_agent(eng, run, provider, ToolRegistry([]), _sandbox(), graph, audit,
                       budget=Budget(), events=sink, specialist_pool=[NmapTool()])

    # The guard denied the child's out-of-scope choice; nothing was scanned.
    assert graph.findings == [] and result.findings == 0
    assert any(e.type == EventType.scope_decision and e.allowed is False for e in audit.events)
    # The delegation still closed out cleanly for the orchestrator.
    assert any(e.kind == RunEventKind.subagent_finished for e in sink.events)


# ---- single-specialist profile (operator-selected, no orchestrator) -----------------------------

def test_single_specialist_profile_runs_directly():
    eng = make_engagement()
    run = Run(id="r1", engagement_id="e1", target="10.0.0.5")
    graph = FakeGraph()
    registry = specialist_registry("scout", [NmapTool()])
    provider = FakeProvider([_nmap("10.0.0.5"), ProviderResponse(text="done")])

    result = run_agent(eng, run, provider, registry, _sandbox(), graph, MemoryAuditSink(),
                       budget=Budget())

    assert len(graph.findings) == 2 and result.findings == 2
