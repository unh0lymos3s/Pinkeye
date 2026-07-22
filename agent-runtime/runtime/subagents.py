"""Specialist sub-agents: focused, single-phase agents the orchestrator delegates to.

A *specialist* owns one pipeline stage (recon / dast / sast / intel / exploit / credentials). It is
just a normal `run_agent` with a focused mission and a tool set narrowed to that stage — so it reuses
the whole propose->validate->execute->observe spine and the scope guard unchanged. What it buys is:

- **Context isolation.** Each specialist runs in its own message list and returns only a short summary
  to the orchestrator, so a long assessment never piles recon + DAST + SAST + exploit output into one
  context window.
- **Specialized prompting.** Each phase gets an expert mission instead of one generalist prompt.
- **Two entry points, one mechanism.** The operator can launch a single specialist directly (a
  "profile"); the orchestrator model can call specialists on demand as tools (`run_specialist`).

Safety is unchanged: every tool a specialist runs still goes through `execute_tool_step` (scope guard +
`requires_flag` + audit). Gated specialists (exploit/credentials) are only *offered* when the signed
scope authorizes them, and they keep the `ask_user(kind="permission")` requirement before intrusive
steps. Sequential today; children already have isolated contexts, so parallel dispatch is a later,
additive change.
"""
from __future__ import annotations

from dataclasses import dataclass

from .llm.base import ToolSpec
from .pipeline import tools_for_stage
from .registry import ToolRegistry


@dataclass(frozen=True)
class Specialist:
    kind: str          # the tool name the orchestrator calls, e.g. "sast"
    stage: str         # the pipeline stage it owns (source of its tool subset)
    summary: str       # one-line description offered to the orchestrator model
    mission: str       # the focused system prompt the specialist runs with
    gated_flag: str | None = None  # scope attribute that must be true to offer it, or None


_RECON_MISSION = (
    "You are a reconnaissance specialist. Map the attack surface of the target: discover live hosts, "
    "open ports, and running services using the recon tools available to you. Call one tool at a time, "
    "read the result, then decide the next step. Stay within the authorized scope; if a call is denied, "
    "pick a different in-scope action. When you have mapped the surface, stop and summarize what you "
    "found (hosts, ports, services) so the orchestrator can plan deeper scans."
)

_DAST_MISSION = (
    "You are a dynamic application security testing (DAST) specialist. Probe the live target for "
    "vulnerabilities using the dynamic scanning tools available to you (web/service scanners, content "
    "discovery). Call one tool at a time, read the result, then decide the next step. Stay within the "
    "authorized scope; if a call is denied, pick a different in-scope action. These scans do not need "
    "operator approval. When you have covered the dynamic surface, stop and summarize the findings."
)

_SAST_MISSION = (
    "You are a static application security testing (SAST) specialist. Analyze the in-scope source "
    "artifact for vulnerabilities, secrets, and vulnerable dependencies using the static analysis tools "
    "available to you. The target is a source path/artifact, not a live host. Call one tool at a time, "
    "read the result, then decide the next step. Stay within the authorized scope. These scans do not "
    "need operator approval. When you have analyzed the artifact, stop and summarize the findings."
)

_INTEL_MISSION = (
    "You are a threat-intelligence specialist. Enrich what earlier passes discovered: look up CVEs for "
    "identified products/versions, check reputation of hashes/indicators, and inspect TLS certificates "
    "using the knowledge tools available to you. Call one tool at a time and stay within scope. When "
    "you have enriched the available data, stop and summarize the intelligence you gathered."
)

_EXPLOIT_MISSION = (
    "You are an exploitation specialist. Validate specific vulnerabilities the orchestrator asked you to "
    "confirm using the exploitation tools available to you. This is intrusive: you MUST call `ask_user` "
    "with kind=\"permission\" and get an explicit go-ahead before launching ANY exploit or "
    "post-exploitation action, and never widen beyond what was approved. Default to check-only "
    "validation. Stay strictly within the authorized scope. When done, stop and summarize precisely "
    "what was validated and what access (if any) was demonstrated."
)

_CREDENTIALS_MISSION = (
    "You are a credential-testing specialist. Test for weak credentials on the in-scope service the "
    "orchestrator identified, using the credential tool available to you. This is intrusive: you MUST "
    "call `ask_user` with kind=\"permission\" and get an explicit go-ahead before launching any "
    "credential attack. Use conservative, low-and-slow settings (spraying, not brute force). Stay "
    "strictly within the authorized scope. When done, stop and summarize the result without echoing any "
    "password material."
)


# The specialist roster. Stage drives the tool subset (via pipeline.tools_for_stage), so a tool that is
# re-mapped to a different stage automatically moves to the matching specialist — one source of truth.
SPECIALISTS: dict[str, Specialist] = {
    s.kind: s
    for s in [
        Specialist("recon", "recon", "Map the attack surface: hosts, ports, services.", _RECON_MISSION),
        Specialist("dast", "dynamic scan", "Dynamically scan the live target for vulnerabilities.",
                   _DAST_MISSION),
        Specialist("sast", "static scan", "Statically analyze an in-scope source artifact.",
                   _SAST_MISSION),
        Specialist("intel", "threat intel", "Enrich findings with CVE/reputation/TLS intelligence.",
                   _INTEL_MISSION),
        Specialist("exploit", "exploitation", "Validate a vulnerability (intrusive — needs approval).",
                   _EXPLOIT_MISSION, gated_flag="allow_exploit"),
        Specialist("credentials", "credentials", "Test for weak credentials (intrusive — needs approval).",
                   _CREDENTIALS_MISSION, gated_flag="allow_credential_attacks"),
    ]
}

SPECIALIST_KINDS = frozenset(SPECIALISTS)

# Shared parameter schema for a specialist call: what to act on, and an optional focus hint.
_SPECIALIST_PARAMS = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Host, IP, URL, or source artifact path to assess."},
        "focus": {
            "type": "string",
            "description": "Optional guidance on what to prioritize, based on earlier passes.",
        },
    },
    "required": ["target"],
}


def is_offered(spec: Specialist, scope) -> bool:
    """A gated specialist is only offered when the signed scope authorizes it — mirroring the flag the
    guard actually enforces. It never *grants* anything; the tool's requires_flag still gates execution."""
    if spec.gated_flag is None:
        return True
    return bool(getattr(scope, spec.gated_flag, False))


def specialist_specs(scope) -> list[ToolSpec]:
    """The specialist sub-agents offered to the orchestrator model, filtered to those the scope allows."""
    return [
        ToolSpec(name=s.kind, description=s.summary, parameters=_SPECIALIST_PARAMS)
        for s in SPECIALISTS.values()
        if is_offered(s, scope)
    ]


def specialist_mission(kind: str, focus: str | None = None) -> str:
    """The focused mission for a specialist, optionally with an operator/orchestrator focus hint appended.
    Used both by the orchestrator dispatch and by a single-specialist operator profile at launch."""
    spec = SPECIALISTS[kind]
    mission = spec.mission
    if focus and str(focus).strip():
        mission = f"{mission}\n\nFocus for this pass: {str(focus).strip()}"
    return mission


def specialist_registry(kind: str, pool: list) -> ToolRegistry:
    """Build the tool registry for a specialist by narrowing the run's tool pool to the specialist's
    stage. `pool` is the operator's per-run tool selection, so an operator who deselected a tool keeps
    it out of every specialist too.

    Unlike `select_tools`, an empty match yields an *empty* registry (not a fall back to all tools): a
    specialist must never inherit another stage's tools just because its own stage had none in the pool.
    """
    names = set(tools_for_stage(SPECIALISTS[kind].stage))
    chosen = [t for t in pool if getattr(t, "name", None) in names]
    return ToolRegistry(chosen)


def run_specialist(
    kind: str,
    target: str,
    focus: str | None,
    *,
    engagement,
    run,
    provider,
    sandbox,
    graph,
    audit,
    db,
    context,
    events,
    memory,
    inbox,
    pool: list,
    remaining_calls: int,
    remaining_tokens: int,
) -> tuple[str, int, int, int]:
    """Run one specialist as a nested, context-isolated `run_agent` and return
    (summary, tool_calls_used, output_tokens, findings) for the orchestrator to fold into its budget.

    The child is sized to the parent's remaining budget so the whole tree stays bounded, and it runs
    with `nested=True` (no run-level plan/status lifecycle) and `subagent=kind` (every event tagged so
    the UI can group the child's activity). The scope guard is untouched — the child's tools enforce it.
    """
    # Imported here (not at module top) to avoid a circular import: agent.py lazily imports this module.
    from .agent import Budget, run_agent

    spec = SPECIALISTS.get(kind)
    if spec is None:
        return (f"unknown specialist '{kind}'", 0, 0, 0)

    child_budget = Budget(
        max_tool_calls=max(1, remaining_calls),
        max_output_tokens=max(1, remaining_tokens),
    )
    registry = specialist_registry(kind, pool)
    child = run_agent(
        engagement,
        run,
        provider,
        registry,
        sandbox,
        graph,
        audit,
        db,
        budget=child_budget,
        mission=specialist_mission(kind, focus),
        context=context,
        events=events,
        memory=memory,
        inbox=inbox,
        seed_target=target,
        nested=True,
        subagent=kind,
    )
    summary = _specialist_summary(kind, child)
    return (summary, child.tool_calls_used, child.output_tokens, child.findings)


def _specialist_summary(kind: str, child) -> str:
    """A compact result line the orchestrator sees instead of the specialist's raw transcript."""
    reason = child.stop_reason or "finished"
    return (
        f"{kind} specialist {reason}: {child.findings} finding(s) recorded across "
        f"{child.tool_calls_used} tool call(s). See the transcript for details."
    )
