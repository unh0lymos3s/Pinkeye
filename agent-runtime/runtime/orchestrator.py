"""Tool execution under the harness spine: authorize -> sandbox -> hash + audit -> normalize ->
write topology + findings to the graph and durable store. Every step emits an audit event so the
run is replayable.

`execute_tool_step` runs exactly one tool and is shared by two callers: `run_scan` (the deterministic
single-tool path) and the LLM agent loop (many steps). Neither can bypass the scope guard.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.audit import AuditEvent, AuditSink, EventType, hash_output
from app.enrich import enrich_finding
from app.models import Engagement, Finding, Intensity, Run, RunStatus
from app.scope import authorize

from .egress import EgressPolicy
from .sandbox import DockerSandbox
from .tools.base import ServiceObservation, Tool


def _audit(sink: AuditSink, engagement_id: str, run_id: str, **kwargs) -> None:
    sink.append(AuditEvent(engagement_id=engagement_id, run_id=run_id, **kwargs))


@dataclass
class StepResult:
    allowed: bool
    reason: str = ""
    services: list[ServiceObservation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    note: str = ""  # informational text from knowledge tools, surfaced to the model
    error: str | None = None
    # Cross-run network-memory diff produced by this step (if a memory engine is wired in), so the
    # caller can surface "what changed" without re-querying. None when no memory is attached.
    memory_delta: object | None = None


def execute_tool_step(
    engagement: Engagement,
    run: Run,
    tool: Tool,
    target: str,
    intensity: Intensity,
    sandbox: DockerSandbox,
    graph,
    audit: AuditSink,
    db=None,
    context: dict | None = None,
    memory=None,
) -> StepResult:
    """Run one tool against one target. Returns what was found so a caller (or the model) can react.
    Does not touch run.status — that belongs to the caller, which may run many steps per run.
    `context` carries optional extras (auth profile, exploit options) for tools that accept it.
    `memory`, if provided, is the cross-run NetworkMemory: a persistence concern beside the existing
    graph/db writes, guarded by `memory is not None`, so the security-critical control flow is
    unchanged whether or not a memory engine is attached."""
    context = context or {}
    surface = getattr(tool, "surface", "network")

    # 1a. Intrusive tools require an explicit, signed authorization flag in the scope. This is a hard
    #     code gate on top of the scope guard: without it, exploitation/credential attacks are refused.
    flag = getattr(tool, "requires_flag", None)
    if flag and not getattr(engagement.scope, flag, False):
        reason = f"{tool.name} requires '{flag}' authorization in the signed scope"
        _audit(audit, engagement.id, run.id, type=EventType.scope_decision, tool=tool.name,
               target=target, allowed=False, detail=reason)
        return StepResult(allowed=False, reason=reason)

    # 1b. Authorize the target. Network->CIDRs/domains, artifact->paths, knowledge->no target.
    decision = authorize(engagement.scope, target, intensity, surface=surface)
    _audit(audit, engagement.id, run.id, type=EventType.scope_decision, tool=tool.name,
           target=target, allowed=decision.allowed, detail=decision.reason)
    if not decision.allowed:
        return StepResult(allowed=False, reason=decision.reason)

    # 2. Execute — in-process for local tools (lookups, RPC clients), in the sandbox otherwise.
    _audit(audit, engagement.id, run.id, type=EventType.tool_started, tool=tool.name, target=target)
    try:
        if getattr(tool, "local", False):
            out = tool.run_local(target=target, intensity=intensity, context=context,
                                 engagement_id=engagement.id, run_id=run.id)
            _audit(audit, engagement.id, run.id, type=EventType.tool_finished, tool=tool.name,
                   target=target, detail=f"local: {len(out.findings)} findings")
        elif getattr(tool, "mcp", None) is not None:
            # MCP-backed execution: authorization/flag/audit above already ran (identical to a
            # sandboxed tool), so the MCP server only ever receives an in-scope target. This is a
            # distinct trust boundary from the sandbox — an external server we call, not run — so it
            # gets its own audit detail and no egress policy is applied to our containers.
            out = tool.run_mcp(target=target, intensity=intensity, context=context,
                               engagement_id=engagement.id, run_id=run.id)
            _audit(audit, engagement.id, run.id, type=EventType.tool_finished, tool=tool.name,
                   target=target, detail=f"mcp[{tool.mcp.command}:{tool.mcp.tool}]: {len(out.findings)} findings")
        else:
            command = (
                tool.build_command(target, intensity, context)
                if getattr(tool, "wants_context", False)
                else tool.build_command(target, intensity)
            )
            # SAST tools analyze source mounted read-only at /src; the target path is that mount.
            # Network tools get a per-job egress allow-list from the same scope (defense in depth).
            source_dir = target if surface == "artifact" else None
            egress = None if surface in ("artifact", "knowledge") else EgressPolicy.from_scope(engagement.scope)
            result = sandbox.run(tool.image, command, source_dir=source_dir, egress=egress)
            _audit(audit, engagement.id, run.id, type=EventType.tool_finished, tool=tool.name,
                   target=target, output_sha256=hash_output(result.stdout), detail=f"exit={result.exit_code}")
            out = tool.parse(result.stdout, engagement_id=engagement.id, run_id=run.id, target=target)
    except Exception as exc:
        return StepResult(allowed=True, error=str(exc))

    # 3. Persist topology + findings to the graph and (if configured) the durable store.
    for svc in out.services:
        graph.upsert_service(engagement.id, svc.address, svc.port, svc.proto, svc.service,
                             svc.product, run.id)
        if db is not None:
            db.upsert_service(engagement.id, svc.address, svc.port, svc.proto, svc.service, svc.product)
    for finding in out.findings:
        enrich_finding(finding)  # attach CVSS score + ATT&CK technique before persisting
        graph.record_finding(finding)
        if db is not None:
            db.record_finding(finding)
        _audit(audit, engagement.id, run.id, type=EventType.finding_recorded, tool=finding.source_tool,
               target=finding.target, detail=f"{finding.severity.value}: {finding.title}")

    # 4. Cross-run memory (optional): record what this observation changed vs the persisted map. Runs
    #    after the authoritative graph/db writes and never affects them — a memory failure is swallowed
    #    so it can't fail a run or influence authorization.
    delta = None
    if memory is not None:
        try:
            delta = memory.observe(engagement.id, run.id, out.services, out.findings)
        except Exception:
            delta = None

    return StepResult(allowed=True, services=out.services, findings=out.findings, note=out.note,
                      memory_delta=delta)


def run_scan(
    engagement: Engagement,
    run: Run,
    tool: Tool,
    intensity: Intensity,
    sandbox: DockerSandbox,
    graph,
    audit: AuditSink,
    db=None,
    context: dict | None = None,
    memory=None,
) -> Run:
    """Deterministic single-tool run (Phase 1 path). Wraps one execute_tool_step and manages status.
    `memory`, if provided, records what this scan changed in the cross-run map so single-tool runs
    feed the "brain" just like agent runs — still a persistence concern beside the graph/db writes,
    never touching authorization."""

    def _set_status(status: RunStatus) -> None:
        run.status = status
        if db is not None:
            db.set_run_status(run.id, status.value)

    step = execute_tool_step(
        engagement, run, tool, run.target, intensity, sandbox, graph, audit, db, context, memory
    )
    if not step.allowed:
        _set_status(RunStatus.rejected)
        _audit(audit, engagement.id, run.id, type=EventType.run_status, detail=f"rejected: {step.reason}")
    elif step.error:
        _set_status(RunStatus.failed)
        _audit(audit, engagement.id, run.id, type=EventType.run_status, detail=f"failed: {step.error}")
    else:
        _set_status(RunStatus.completed)
        _audit(audit, engagement.id, run.id, type=EventType.run_status, detail="completed")
    return run
