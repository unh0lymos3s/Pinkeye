"""Tool execution under the harness spine: authorize -> sandbox -> hash + audit -> normalize ->
write topology + findings to the graph and durable store. Every step emits an audit event so the
run is replayable.

`execute_tool_step` runs exactly one tool and is shared by two callers: `run_scan` (the deterministic
single-tool path) and the LLM agent loop (many steps). Neither can bypass the scope guard.

The `db` sink is opaque here on purpose: it is whatever write interface the caller handed the run,
and this module knows only its method names. In the control plane it is a *tenant-bound view* of the
process-wide `PersistenceSink` (`PersistenceSink.for_tenant`), so multi-tenant row stamping happens
without any tenant argument reaching this file. Resist adding one — a run has exactly one tenant for
its whole lifetime, so it belongs to the sink, not to each call.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.audit import AuditEvent, AuditSink, EventType, hash_output
from app.enrich import enrich_finding
from app.models import Engagement, Finding, Intensity, Run, RunStatus
from app.scope import authorize

from .egress import EgressPolicy
from .sandbox import DockerSandbox
from .tools.base import ServiceObservation, Tool, ToolOutput


def _audit(sink: AuditSink, engagement_id: str, run_id: str, **kwargs) -> None:
    sink.append(AuditEvent(engagement_id=engagement_id, run_id=run_id, **kwargs))


def _audit_many(sink: AuditSink, events: list[AuditEvent]) -> None:
    """Append a batch of audit events in one round trip.

    The append-only guarantee is untouched — the events are still never updated or deleted, they are
    just written in one transaction instead of borrowing a connection per event. `append_many` is
    part of the `AuditSink` protocol, so unlike the graph/db sinks below this needs no feature
    detection — every sink implements it."""
    if not events:
        return
    sink.append_many(events)


def _persist_services(graph, db, engagement_id: str, run_id: str, services: list) -> None:
    """Write the step's topology in one round trip per store, falling back to the row-at-a-time
    methods when a store does not (yet) expose the bulk form."""
    if not services:
        return
    if hasattr(graph, "upsert_services"):
        graph.upsert_services(engagement_id, services, run_id=run_id)
    else:
        for svc in services:
            graph.upsert_service(engagement_id, svc.address, svc.port, svc.proto, svc.service,
                                 svc.product, run_id)
    if db is None:
        return
    if hasattr(db, "upsert_services"):
        db.upsert_services(engagement_id,
                           [(s.address, s.port, s.proto, s.service, s.product) for s in services])
    else:
        for svc in services:
            db.upsert_service(engagement_id, svc.address, svc.port, svc.proto, svc.service, svc.product)


def _persist_findings(graph, db, findings: list) -> None:
    """Write the step's findings in one round trip per store. Callers must have run `enrich_finding`
    over the list first — the persisted row carries the CVSS score and ATT&CK technique."""
    if not findings:
        return
    if hasattr(graph, "record_findings"):
        graph.record_findings(findings)
    else:
        for finding in findings:
            graph.record_finding(finding)
    if db is None:
        return
    if hasattr(db, "record_findings"):
        db.record_findings(findings)
    else:
        for finding in findings:
            db.record_finding(finding)


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
    # Round 6 — WS A: the signal that makes a false negative visible. A sandboxed tool that exits 0
    # with empty stdout (or an empty/missing artifact) looks identical to a clean scan unless
    # something downstream can tell the two apart — these three fields are that something.
    # `exit_code` is None for local/mcp tools: they never touch the sandbox, so there is no process
    # exit code to report, and B's "no output" check can key on `exit_code is not None` alone to skip
    # them entirely. `output_bytes` is the length of whatever was actually handed to `tool.parse` —
    # stdout, or the extracted artifact when the tool declares `artifact_path` — except for local/mcp
    # tools, where it is derived from their ToolOutput.note instead of left at the 0 default, so a
    # knowledge tool that legitimately returns only a note is never mistaken for "produced nothing."
    # `parsed_ok` is False only when the payload was non-empty but `tool.parse` raised on it — a
    # malformed or hostile report, which is a finding about the target, not the same thing as a clean
    # empty scan or a sandbox-level failure (those still take the `error` path above).
    exit_code: int | None = None
    output_bytes: int = 0
    parsed_ok: bool = True


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
            exit_code = None  # no sandbox involved — see StepResult.exit_code
            # A local tool's real "output" is its note (or, failing that, whatever it did produce);
            # never 0, so it can never look like the "tool ran and produced nothing" case below.
            output_bytes = len(out.note.encode("utf-8")) if out.note else 1
            parsed_ok = True
            _audit(audit, engagement.id, run.id, type=EventType.tool_finished, tool=tool.name,
                   target=target, detail=f"local: {len(out.findings)} findings")
        elif getattr(tool, "mcp", None) is not None:
            # MCP-backed execution: authorization/flag/audit above already ran (identical to a
            # sandboxed tool), so the MCP server only ever receives an in-scope target. This is a
            # distinct trust boundary from the sandbox — an external server we call, not run — so it
            # gets its own audit detail and no egress policy is applied to our containers.
            out = tool.run_mcp(target=target, intensity=intensity, context=context,
                               engagement_id=engagement.id, run_id=run.id)
            exit_code = None  # no sandbox involved — see StepResult.exit_code
            output_bytes = len(out.note.encode("utf-8")) if out.note else 1
            parsed_ok = True
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
            # Round 6 — WS A: optional per-tool sandbox needs, read via getattr so tools that don't
            # declare any of these (still most of them) run exactly as before.
            artifact_path = getattr(tool, "artifact_path", None)
            result = sandbox.run(
                tool.image, command, source_dir=source_dir, egress=egress,
                tmpfs=getattr(tool, "tmpfs", None) or None,
                artifact_path=artifact_path,
                mem_limit=getattr(tool, "mem_limit", None),
                timeout_seconds=getattr(tool, "timeout_seconds", None),
            )
            exit_code = result.exit_code
            if artifact_path is not None:
                # Some tools (gitleaks, ZAP — see the round-6 contract) cannot write their report to
                # stdout at all; the artifact pulled out of the container after it exits is the only
                # copy of what they found, so it — not stdout — is what gets parsed and hashed.
                payload = result.artifact or b""
            else:
                payload = result.stdout
            output_bytes = len(payload)
            detail = f"exit={result.exit_code}"
            if artifact_path is None and getattr(result, "stdout_truncated", False):
                # The parse below only saw the first EYE_TOOL_MAX_OUTPUT_BYTES bytes; say so in the
                # audit log, so a partial result is never mistaken for a complete one on replay.
                detail += f" (stdout truncated at {len(result.stdout)} bytes)"
            elif artifact_path is not None and getattr(result, "artifact_missing", False):
                detail += " (artifact missing: tool never wrote it)"
            elif artifact_path is not None and getattr(result, "artifact_truncated", False):
                detail += f" (artifact truncated at {len(payload)} bytes)"
            _audit(audit, engagement.id, run.id, type=EventType.tool_finished, tool=tool.name,
                   target=target, output_sha256=hash_output(payload), detail=detail)
            try:
                out = tool.parse(payload, engagement_id=engagement.id, run_id=run.id, target=target)
                parsed_ok = True
            except Exception:
                # Distinguish "the sandbox/tool infrastructure failed" (the outer except below, which
                # becomes StepResult.error and fails the step) from "the tool ran, exited, produced
                # bytes, and the parser choked on them." A malformed or hostile report is a finding
                # about the target's tooling, not an infrastructure failure — it must not collapse
                # into the same generic error path. An empty ToolOutput keeps step 3 below a no-op;
                # parsed_ok=False is what tells the layer above that the emptiness came from a parse
                # failure rather than a clean scan.
                out = ToolOutput()
                parsed_ok = False
    except Exception as exc:
        return StepResult(allowed=True, error=str(exc))

    # 3. Persist topology + findings to the graph and (if configured) the durable store.
    #    Written as batches: one `nmap -p-` can yield a service *and* a finding per open port, and a
    #    row-at-a-time write path turned that into thousands of Neo4j sessions and Postgres
    #    connection checkouts inside a single step, serialized on the run thread. The bulk methods
    #    keep the identical MERGE/upsert keys, so nothing duplicates and nothing is written that the
    #    singular path would not have written; they are feature-detected because the graph/db objects
    #    here are also fakes in tests and older sinks in the field.
    for finding in out.findings:
        enrich_finding(finding)  # attach CVSS score + ATT&CK technique before persisting
    _persist_services(graph, db, engagement.id, run.id, out.services)
    _persist_findings(graph, db, out.findings)
    _audit_many(audit, [
        AuditEvent(engagement_id=engagement.id, run_id=run.id, type=EventType.finding_recorded,
                   tool=finding.source_tool, target=finding.target,
                   detail=f"{finding.severity.value}: {finding.title}")
        for finding in out.findings
    ])

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
                      memory_delta=delta, exit_code=exit_code, output_bytes=output_bytes,
                      parsed_ok=parsed_ok)


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
    cancels=None,
) -> Run:
    """Deterministic single-tool run (Phase 1 path). Wraps one execute_tool_step and manages status.
    `memory`, if provided, records what this scan changed in the cross-run map so single-tool runs
    feed the "brain" just like agent runs — still a persistence concern beside the graph/db writes,
    never touching authorization.

    `cancels` is the control-plane's RunCancels registry (round 5 — abort). A scan is a single tool
    step, so there is no loop to poll: the abort lands as `sandbox.abort()` killing the in-flight
    container, and the only thing left to get right is the *verdict*. Without the check below, a
    killed container surfaces as a nonzero exit or empty output and the run reports `failed` — which
    reads as "the tool broke" when in fact the operator stopped it. The status is the whole point of
    an abort button, so the flag is consulted before the step's own outcome is classified."""

    def _set_status(status: RunStatus) -> None:
        run.status = status
        if db is not None:
            db.set_run_status(run.id, status.value)

    step = execute_tool_step(
        engagement, run, tool, run.target, intensity, sandbox, graph, audit, db, context, memory
    )
    if cancels is not None and cancels.is_cancelled(run.id):
        _set_status(RunStatus.aborted)
        _audit(audit, engagement.id, run.id, type=EventType.run_status, detail="aborted by operator")
    elif not step.allowed:
        _set_status(RunStatus.rejected)
        _audit(audit, engagement.id, run.id, type=EventType.run_status, detail=f"rejected: {step.reason}")
    elif step.error:
        _set_status(RunStatus.failed)
        _audit(audit, engagement.id, run.id, type=EventType.run_status, detail=f"failed: {step.error}")
    else:
        _set_status(RunStatus.completed)
        _audit(audit, engagement.id, run.id, type=EventType.run_status, detail="completed")
    return run
