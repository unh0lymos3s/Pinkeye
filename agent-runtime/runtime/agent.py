"""The LLM planning loop: propose -> validate -> execute -> observe -> decide.

The model chooses which tool to run against which target; the harness validates every choice against
the scope guard, runs it in the sandbox, persists results, and feeds a short summary back. The model
never sees a shell and can never widen scope — an out-of-scope proposal comes back as a denial it must
work around. Token and tool-call budgets bound cost and stop runaway loops.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from app.audit import AuditSink
from app.models import Engagement, Intensity, Run, RunStatus

from .llm.base import LLMProvider, Message, ToolSpec
from .llm.refusal import is_refusal
from .orchestrator import execute_tool_step
from .pipeline import STAGES, stage_of
from .registry import ToolRegistry
from .sandbox import DockerSandbox

DEFAULT_MISSION = (
    "You are a penetration-testing planning agent. Discover the attack surface of the target and "
    "identify vulnerabilities using the available tools. Call one tool at a time, read the result, "
    "then decide the next step. Stay within the authorized scope; if a call is denied, pick a "
    "different in-scope action. When you have covered the surface, stop and summarize.\n\n"
    "You can talk to the human operator with the `ask_user` tool, which pauses the run and returns "
    "their reply. You MUST call `ask_user` with kind=\"permission\" to get an explicit go-ahead "
    "before any intrusive step — anything in the exploitation or credentials stages (exploit, "
    "post_exploit, credential_attack). Do not launch an intrusive tool until the operator approves. "
    "Use kind=\"recommendation\" to propose a next action and let the operator steer, and "
    "kind=\"question\" for anything else you need from them. Recon, dynamic (DAST) and static (SAST) "
    "scanning do not need approval — run those autonomously within scope."
)

# The operator-conversation tool. It is not a sandbox tool: the agent loop handles it inline by
# emitting an `ask` event and blocking on the run inbox for the reply. Always offered to the model
# (independent of the tool-library selection) so it can always reach the human.
ASK_USER_SPEC = ToolSpec(
    name="ask_user",
    description=(
        "Pause and ask the human operator a question in the chat, then wait for their reply. Use "
        "kind='permission' to request an explicit approve/deny before an intrusive/exploitation "
        "step (REQUIRED before exploit, post_exploit, or credential_attack); kind='recommendation' "
        "to propose a next action; kind='question' for anything else. The operator's reply is "
        "returned to you as the result."
    ),
    parameters={
        "type": "object",
        "properties": {
            "question": {"type": "string", "description": "What to ask the operator, in plain language."},
            "kind": {
                "type": "string",
                "enum": ["permission", "recommendation", "question"],
                "description": "permission = needs approve/deny; recommendation = suggest an action; question = free-form.",
            },
            "action": {"type": "string", "description": "The specific next action you propose to take, if any."},
        },
        "required": ["question"],
    },
)

# How long the run thread blocks waiting for an operator reply before proceeding autonomously (and
# never taking an intrusive action, since that still needs approval). Read from the env at call time.
DEFAULT_ASK_TIMEOUT_SECONDS = 600


@dataclass
class Budget:
    # Hard backstop on a run, larger than a single-tool scan needs but never unlimited — a runaway
    # loop still terminates. Defaults are env-tunable so an operator can size them to an engagement.
    max_tool_calls: int = 40
    max_output_tokens: int = 200000

    @classmethod
    def from_env(cls) -> "Budget":
        """Build a Budget from EYE_AGENT_MAX_TOOL_CALLS / EYE_AGENT_MAX_OUTPUT_TOKENS, falling back
        to the defaults (and ignoring unparseable values) so a bad env var can't disable the cap."""
        return cls(
            max_tool_calls=_env_int("EYE_AGENT_MAX_TOOL_CALLS", cls.max_tool_calls),
            max_output_tokens=_env_int("EYE_AGENT_MAX_OUTPUT_TOKENS", cls.max_output_tokens),
        )


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass
class AgentResult:
    tool_calls_used: int = 0
    output_tokens: int = 0
    findings: int = 0
    stop_reason: str = ""


def _summarize(step) -> str:
    """The only thing the model sees from a tool run — a short, structured summary, never raw output."""
    if not step.allowed:
        return f"DENIED by scope guard: {step.reason}. Choose a different in-scope target."
    if step.error:
        return f"tool error: {step.error}"
    if step.note:  # knowledge tools return their answer directly
        return step.note
    titles = ", ".join(f.title for f in step.findings[:10]) or "no findings"
    return f"{len(step.services)} services, {len(step.findings)} findings: {titles}"


def _authorized_stages(scope) -> tuple[list[str], list[str]]:
    """Split the presentation stages into authorized vs gated for the plan event. Gating mirrors the
    signed-scope flags the guard actually enforces — it never *grants* anything, only reflects it."""
    gated: list[str] = []
    if not getattr(scope, "allow_exploit", False):
        gated.append("exploitation")
    if not getattr(scope, "allow_credential_attacks", False):
        gated.append("credentials")
    authorized = [s for s in STAGES if s not in gated]
    return authorized, gated


def run_agent(
    engagement: Engagement,
    run: Run,
    provider: LLMProvider,
    registry: ToolRegistry,
    sandbox: DockerSandbox,
    graph,
    audit: AuditSink,
    db=None,
    budget: Budget | None = None,
    mission: str = DEFAULT_MISSION,
    context: dict | None = None,
    events=None,
    memory=None,
    inbox=None,
) -> AgentResult:
    budget = budget or Budget.from_env()
    result = AgentResult()

    def emit(kind: str, **data) -> None:
        # Presentation-only event stream; a missing/broken sink never affects the run.
        if events is None:
            return
        try:
            events.emit(run.id, engagement.id, kind, **data)
        except Exception:
            pass

    def _set_status(status: RunStatus) -> None:
        run.status = status
        if db is not None:
            db.set_run_status(run.id, status.value)
        emit("status", status=status.value)

    authorized, gated = _authorized_stages(engagement.scope)
    emit(
        "plan",
        stages=STAGES,
        authorized_stages=authorized,
        gated_stages=gated,
        seed_target=run.target,
        budget={"max_tool_calls": budget.max_tool_calls, "max_output_tokens": budget.max_output_tokens},
    )

    _set_status(RunStatus.running)
    system_prompt = mission
    # Memory-in: seed the agent with the remembered network map so it builds on prior runs instead of
    # starting blind. This is guidance only — every tool call is still scope-checked, so a remembered
    # host that has fallen out of scope can never be re-authorized by its presence here.
    known_map = _known_map_message(memory, engagement.id)
    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=f"Seed target: {run.target}. Begin."),
    ]
    if known_map:
        messages.insert(1, Message(role="system", content=known_map))
    # Always offer ask_user alongside the (possibly narrowed) tool set so the agent can reach the
    # operator regardless of the tool-library selection.
    specs = [*registry.specs(), ASK_USER_SPEC]

    # Surface a refusal-aware provider's reinforce/fallback transitions into the event stream.
    if hasattr(provider, "on_refusal"):
        provider.on_refusal = lambda data: emit("refusal", **data)

    stop_status = RunStatus.completed
    while True:
        try:
            resp = provider.complete(messages, specs)
        except Exception as exc:
            # The model/provider was unreachable or errored. Surface it as an event + failed status
            # (never a silent hang): the UI and logs must show *why* the run stopped.
            emit("error", scope="llm", message=f"{type(exc).__name__}: {exc}")
            result.stop_reason = f"llm error: {type(exc).__name__}"
            stop_status = RunStatus.failed
            break
        result.output_tokens += resp.output_tokens
        if resp.text.strip():
            emit("thinking", text=resp.text)

        if not resp.tool_calls:
            # A refusal (apologetic text, no tool call) is not the same as being done: mark it so
            # the transcript shows the model declined rather than silently "finishing" empty-handed.
            if resp.text.strip() and is_refusal(resp.text):
                emit("refusal", stage="final", provider="model", text=resp.text)
                result.stop_reason = "model refused"
            else:
                result.stop_reason = "agent finished"
            break

        messages.append(Message(role="assistant", content=resp.text, tool_calls=resp.tool_calls))
        for tc in resp.tool_calls:
            if tc.name == "ask_user":
                # Interactive step: emit the question, block for the operator's reply, feed it back.
                summary = _ask_user(engagement, run, tc, emit, inbox)
            else:
                summary = _run_one(engagement, run, tc, registry, sandbox, graph, audit, db, result,
                                   context, emit, memory)
            messages.append(Message(role="tool", content=summary, tool_call_id=tc.id))
            result.tool_calls_used += 1

        if result.tool_calls_used >= budget.max_tool_calls:
            result.stop_reason = "tool-call budget reached"
            break
        if result.output_tokens >= budget.max_output_tokens:
            result.stop_reason = "token budget reached"
            break

    _set_status(stop_status)
    return result


def _known_map_message(memory, engagement_id: str) -> str:
    """Render the remembered network map into a compact system message, or '' if there's nothing to
    inject. The model sees a summary of devices/service-clusters/exploitable endpoints and recent
    changes — never raw tool output — preserving the summary-only feedback contract."""
    if memory is None:
        return ""
    try:
        snap = memory.snapshot(engagement_id)
    except Exception:
        return ""
    devices = snap.get("devices") if isinstance(snap, dict) else None
    if not devices:
        return ""
    lines = [
        "Known network map from prior runs (guidance only — every action is still scope-checked). "
        "Prioritize changed and exploitable targets; you need not rediscover what is already known."
    ]
    for dev in devices[:40]:
        addr = dev.get("address", "?")
        status = dev.get("status", "")
        svcs = dev.get("services", [])
        svc_txt = ", ".join(
            f"{s.get('port')}/{s.get('proto', 'tcp')} {s.get('service', '')}".strip()
            + ("  ⚠exploitable" if s.get("exploitable") else "")
            for s in svcs[:20]
        ) or "no services recorded"
        flag = " [TARGET]" if dev.get("is_target") else ""
        badge = f" ({status})" if status else ""
        lines.append(f"- {addr}{badge}{flag}: {svc_txt}")
    changes = snap.get("recent_changes") if isinstance(snap, dict) else None
    if changes:
        lines.append("Changes since last run: " + "; ".join(str(c) for c in changes[:20]))
    return "\n".join(lines)


def _ask_user(engagement, run, tc, emit, inbox) -> str:
    """Handle an `ask_user` call: emit the question, block the run thread on the inbox for the
    operator's reply, echo it into the transcript, and return it to the model. On timeout (or with no
    inbox wired), proceed autonomously — but the model is told not to take intrusive actions unasked."""
    args = tc.arguments or {}
    question = str(args.get("question", "")).strip() or "Awaiting your input."
    kind = str(args.get("kind", "question")).strip() or "question"
    action = args.get("action")
    emit("ask", question=question, kind=kind, action=action)

    timeout = _env_int("EYE_AGENT_ASK_TIMEOUT", DEFAULT_ASK_TIMEOUT_SECONDS)
    reply = inbox.wait(run.id, timeout) if inbox is not None else None
    if reply is None or not str(reply).strip():
        note = (
            "(operator did not respond — proceeding autonomously within authorized scope; do NOT "
            "run any intrusive/exploitation tool without explicit approval)"
        )
        emit("user_reply", text=note, auto=True)
        return note
    reply = str(reply).strip()
    emit("user_reply", text=reply)
    return f"Operator replied: {reply}"


def _run_one(engagement, run, tc, registry, sandbox, graph, audit, db, result, context, emit, memory) -> str:
    """Validate + execute a single tool call the model proposed, returning the summary it will see.
    Emits the presentation events (tool_call / tool_started / finding / tool_finished / memory_delta)
    around the unchanged execute_tool_step spine."""
    tool = registry.get(tc.name)
    if tool is None:
        emit("tool_finished", tool=tc.name, error=f"unknown tool '{tc.name}'", denied=False)
        return f"unknown tool '{tc.name}'"
    target = str(tc.arguments.get("target", "")).strip()
    if not target:
        emit("tool_finished", tool=tc.name, error="missing 'target' argument", denied=False)
        return "missing 'target' argument"
    try:
        intensity = Intensity(tc.arguments.get("intensity", "light"))
    except ValueError:
        intensity = Intensity.light  # ignore a bad intensity rather than fail the step

    stage = stage_of(tool.name)
    emit("tool_call", tool=tool.name, target=target, intensity=intensity.value, stage=stage)
    emit("tool_started", tool=tool.name, target=target, stage=stage)

    step = execute_tool_step(engagement, run, tool, target, intensity, sandbox, graph, audit, db,
                             context, memory)
    result.findings += len(step.findings)

    for f in step.findings:
        emit("finding", tool=f.source_tool or tool.name, target=f.target, title=f.title,
             severity=f.severity.value, category=f.category, cve=f.cve, state=f.state.value)

    summary = _summarize(step)
    emit("tool_finished", tool=tool.name, target=target, stage=stage, summary=summary,
         denied=not step.allowed, error=step.error,
         services=len(step.services), findings=len(step.findings))

    # Memory-out: surface each observed change so the chat shows a live "network changes" feed.
    delta = getattr(step, "memory_delta", None)
    if delta is not None:
        for entry in _delta_events(delta):
            emit("memory_delta", **entry)

    return summary


def _delta_events(delta) -> list[dict]:
    """Flatten a MemoryDelta into per-change event payloads. Tolerates either a plain dict (test
    sinks) or the MemoryDelta dataclass so agent.py stays decoupled from the memory module."""
    out: list[dict] = []
    buckets = (
        ("added", delta.get("added") if isinstance(delta, dict) else getattr(delta, "added", [])),
        ("changed", delta.get("changed") if isinstance(delta, dict) else getattr(delta, "changed", [])),
        ("removed", delta.get("removed") if isinstance(delta, dict) else getattr(delta, "removed", [])),
        ("newly_exploitable",
         delta.get("newly_exploitable") if isinstance(delta, dict) else getattr(delta, "newly_exploitable", [])),
    )
    for change, items in buckets:
        for item in items or []:
            payload = dict(item) if isinstance(item, dict) else {"key": str(item)}
            # A memory entity carries its own `kind` (host/service/...), which would collide with the
            # event `kind` when splatted into emit(). Preserve it under a non-colliding key.
            if "kind" in payload:
                payload["entity_kind"] = payload.pop("kind")
            payload["change"] = change
            out.append(payload)
    return out
