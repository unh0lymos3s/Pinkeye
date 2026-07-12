"""The LLM planning loop: propose -> validate -> execute -> observe -> decide.

The model chooses which tool to run against which target; the harness validates every choice against
the scope guard, runs it in the sandbox, persists results, and feeds a short summary back. The model
never sees a shell and can never widen scope — an out-of-scope proposal comes back as a denial it must
work around. Token and tool-call budgets bound cost and stop runaway loops.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.audit import AuditSink
from app.models import Engagement, Intensity, Run, RunStatus

from .llm.base import LLMProvider, Message
from .orchestrator import execute_tool_step
from .registry import ToolRegistry
from .sandbox import DockerSandbox

DEFAULT_MISSION = (
    "You are a penetration-testing planning agent. Discover the attack surface of the target and "
    "identify vulnerabilities using the available tools. Call one tool at a time, read the result, "
    "then decide the next step. Stay within the authorized scope; if a call is denied, pick a "
    "different in-scope action. When you have covered the surface, stop and summarize."
)


@dataclass
class Budget:
    max_tool_calls: int = 20
    max_output_tokens: int = 20000


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
) -> AgentResult:
    budget = budget or Budget()
    result = AgentResult()

    def _set_status(status: RunStatus) -> None:
        run.status = status
        if db is not None:
            db.set_run_status(run.id, status.value)

    _set_status(RunStatus.running)
    messages = [
        Message(role="system", content=mission),
        Message(role="user", content=f"Seed target: {run.target}. Begin."),
    ]
    specs = registry.specs()

    while True:
        resp = provider.complete(messages, specs)
        result.output_tokens += resp.output_tokens

        if not resp.tool_calls:
            result.stop_reason = "agent finished"
            break

        messages.append(Message(role="assistant", content=resp.text, tool_calls=resp.tool_calls))
        for tc in resp.tool_calls:
            summary = _run_one(engagement, run, tc, registry, sandbox, graph, audit, db, result, context)
            messages.append(Message(role="tool", content=summary, tool_call_id=tc.id))
            result.tool_calls_used += 1

        if result.tool_calls_used >= budget.max_tool_calls:
            result.stop_reason = "tool-call budget reached"
            break
        if result.output_tokens >= budget.max_output_tokens:
            result.stop_reason = "token budget reached"
            break

    _set_status(RunStatus.completed)
    return result


def _run_one(engagement, run, tc, registry, sandbox, graph, audit, db, result, context=None) -> str:
    """Validate + execute a single tool call the model proposed, returning the summary it will see."""
    tool = registry.get(tc.name)
    if tool is None:
        return f"unknown tool '{tc.name}'"
    target = str(tc.arguments.get("target", "")).strip()
    if not target:
        return "missing 'target' argument"
    try:
        intensity = Intensity(tc.arguments.get("intensity", "light"))
    except ValueError:
        intensity = Intensity.light  # ignore a bad intensity rather than fail the step

    step = execute_tool_step(engagement, run, tool, target, intensity, sandbox, graph, audit, db, context)
    result.findings += len(step.findings)
    return _summarize(step)
