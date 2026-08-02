"""Specialist sub-agents: focused, single-phase agents the orchestrator delegates to.

A *specialist* is a named persona (`runtime/personas.py`) that owns one pipeline stage (recon / dast
/ sast / intel / exploit / credentials) and an explicit tool list. It is just a normal `run_agent`
with the persona's mission and a tool set narrowed to the persona's `tools` — so it reuses the whole
propose->validate->execute->observe spine and the scope guard unchanged. What it buys is:

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

from .llm.base import ToolSpec
from .personas import Persona, load_personas
from .registry import ToolRegistry

# SPECIALISTS is a view over the loaded persona roster: every persona except the orchestrator (which
# delegates rather than running tools) and the generalist (which runs solo over the full toolkit, not
# as something the orchestrator dispatches). Kept as a module-level name — and re-derived from
# `load_personas()` on every import — so the rest of this module, `agent.py`, and `main.py` can keep
# addressing a specialist by id without knowing personas are config-loaded underneath.
SPECIALISTS: dict[str, Persona] = {
    p.id: p for p in load_personas().values() if not p.orchestrator and not p.generalist
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


def is_offered(spec: Persona, scope) -> bool:
    """A gated specialist is only offered when the signed scope authorizes it — mirroring the flag the
    guard actually enforces. It never *grants* anything; the tool's requires_flag still gates execution."""
    if spec.gated_flag is None:
        return True
    return bool(getattr(scope, spec.gated_flag, False))


def specialist_specs(scope) -> list[ToolSpec]:
    """The specialist sub-agents offered to the orchestrator model, filtered to those the scope
    allows. The description reads as the persona ("Scout — maps the ground before anyone steps on
    it.") so the orchestrator model sees the same identity the chat UI will label the dispatch with."""
    return [
        ToolSpec(name=s.id, description=f"{s.label} — {s.tagline}", parameters=_SPECIALIST_PARAMS)
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
    """Build the tool registry for a specialist by narrowing the run's tool pool to the persona's
    explicit `tools` list. `pool` is the operator's per-run tool selection, so an operator who
    deselected a tool keeps it out of every specialist too.

    Unlike `select_tools`, an empty match yields an *empty* registry (not a fall back to all tools): a
    specialist must never inherit another persona's tools just because its own list matched nothing
    in the pool.
    """
    names = set(SPECIALISTS[kind].tools)
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
    cancels=None,
) -> tuple[str, int, int, int, int]:
    """Run one specialist as a nested, context-isolated `run_agent` and return
    (summary, tool_calls_used, output_tokens, input_tokens, findings) for the orchestrator to fold
    into its budget. Input tokens are reported alongside output tokens because the token budget
    charges both — a child that resends a long history costs the tree just as much as one that
    writes a long answer.

    The child is sized to the parent's remaining budget so the whole tree stays bounded, and it runs
    with `nested=True` (no run-level plan/status lifecycle) and `subagent=kind` (every event tagged so
    the UI can group the child's activity). The scope guard is untouched — the child's tools enforce it.

    `cancels` (round 5 — WS A) is threaded straight through to the child's `run_agent` call, unchanged,
    so an operator abort stops a specialist mid-pass instead of letting it burn through its whole
    carved-off budget first — see `_dispatch_specialist` in agent.py, the only caller.
    """
    # Imported here (not at module top) to avoid a circular import: agent.py lazily imports this module.
    from .agent import Budget, run_agent

    spec = SPECIALISTS.get(kind)
    if spec is None:
        return (f"unknown specialist '{kind}'", 0, 0, 0, 0)

    child_budget = Budget(
        max_tool_calls=max(1, remaining_calls),
        # The parent passes what is left of the *combined* input+output allowance.
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
        cancels=cancels,
    )
    summary = _specialist_summary(kind, child)
    return (summary, child.tool_calls_used, child.output_tokens, child.input_tokens, child.findings)


def _specialist_summary(kind: str, child) -> str:
    """A compact result line the orchestrator sees instead of the specialist's raw transcript."""
    reason = child.stop_reason or "finished"
    return (
        f"{kind} specialist {reason}: {child.findings} finding(s) recorded across "
        f"{child.tool_calls_used} tool call(s). See the transcript for details."
    )
