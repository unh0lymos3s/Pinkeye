"""The LLM planning loop: propose -> validate -> execute -> observe -> decide.

The model chooses which tool to run against which target; the harness validates every choice against
the scope guard, runs it in the sandbox, persists results, and feeds a short summary back. The model
never sees a shell and can never widen scope — an out-of-scope proposal comes back as a denial it must
work around. Token and tool-call budgets bound cost and stop runaway loops.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.audit import AuditSink
from app.models import Engagement, Intensity, Run, RunStatus

from .envutil import env_int
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

# The top-level mission when the run is an *orchestrator*: it does not run tools itself, it delegates
# to focused specialist sub-agents (recon/dast/sast/intel/exploit/credentials). Each specialist runs
# in its own isolated context and returns only a short summary, so the orchestrator's context stays
# clean across a long assessment. The orchestrator sequences the passes and composes the final report.
ORCHESTRATOR_MISSION = (
    "You are the lead orchestrator of a security assessment. You do NOT run scanning tools yourself; "
    "instead you delegate to focused specialist sub-agents by calling them as tools. Each specialist "
    "works in its own isolated context and returns a short summary of what it found — you see the "
    "summary, not its raw output.\n\n"
    "Plan the assessment and dispatch specialists one at a time, reading each summary before the next: "
    "start with `recon` to map the attack surface, then `dast` (live web/service scanning) and/or "
    "`sast` (static analysis of source, when an artifact is in scope), then `intel` (CVE/threat-intel "
    "enrichment). Give each specialist a clear `target` and an optional `focus` describing what to "
    "prioritize based on what earlier passes found.\n\n"
    "The `exploit` and `credentials` specialists are intrusive. You MUST call `ask_user` with "
    "kind=\"permission\" and get an explicit go-ahead BEFORE dispatching either of them. Only dispatch "
    "them if they are offered to you (they are withheld unless the engagement scope authorizes them). "
    "When every needed pass is done, stop and summarize the overall findings and attack surface."
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

# How many past exchanges the history keeps verbatim before older ones are rolled up into a single
# summary line (B7). One "block" is an assistant turn plus the tool results answering it; the seed
# user turn and every system message are always preserved. 0 disables compaction entirely.
DEFAULT_HISTORY_BLOCKS = 12
_HISTORY_SUMMARY_CHARS = 4000
_HISTORY_ENTRY_CHARS = 160


@dataclass
class Budget:
    # Hard backstop on a run, larger than a single-tool scan needs but never unlimited — a runaway
    # loop still terminates. Defaults are env-tunable so an operator can size them to an engagement.
    max_tool_calls: int = 40
    # Counted against input + output tokens: resending a growing history is the dominant cost of a
    # long run, so a budget that only saw output tokens could not see (let alone bound) it.
    max_output_tokens: int = 200000

    @classmethod
    def from_env(cls) -> "Budget":
        """Build a Budget from EYE_AGENT_MAX_TOOL_CALLS / EYE_AGENT_MAX_OUTPUT_TOKENS, falling back
        to the defaults (and ignoring unparseable values) so a bad env var can't disable the cap."""
        return cls(
            max_tool_calls=env_int("EYE_AGENT_MAX_TOOL_CALLS", cls.max_tool_calls, minimum=1),
            max_output_tokens=env_int("EYE_AGENT_MAX_OUTPUT_TOKENS", cls.max_output_tokens, minimum=1),
        )


@dataclass
class AgentResult:
    tool_calls_used: int = 0
    output_tokens: int = 0
    # Measured too, and charged to the same budget: `ProviderResponse.input_tokens` already carried
    # this, it was simply never read, so history growth was invisible to the cap meant to bound it.
    input_tokens: int = 0
    findings: int = 0
    stop_reason: str = ""

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


def _no_output(step) -> bool:
    """Round 6 — WS B: true when a step produced literally nothing for the parser to read — the
    silent-zero failure the whole platform was found reporting as a clean scan (gitleaks defaulting
    to git-history mode against a `.git`-less `/src`, trivy/nuclei needing a writable `/tmp` they
    didn't have, zap/nikto/ffuf each failing before they ever touched the target — see
    round6-contract.md). `_summarize` and `_run_one` both need to recognize this identically: one
    picks the model-facing wording, the other decides whether to raise the operator-facing warning,
    and they must never disagree about which steps triggered it.

    Reads `output_bytes` with `getattr(..., None)` rather than assuming the field exists, since
    `StepResult` gaining it is WS-A's change and may land before or after this one; a step that
    predates the field reads as `None`, which correctly never equals 0 and so never trips this. The
    `not findings and not services` guard is redundant with a genuinely empty payload (nothing parses
    findings out of zero bytes) but costs nothing and keeps this from ever firing on a step that
    somehow carries real results alongside a stale/default byte count of 0."""
    if not step.allowed or step.error or step.note:
        return False
    return not step.findings and not step.services and getattr(step, "output_bytes", None) == 0


def _summarize(step) -> str:
    """The only thing the model sees from a tool run — a short, structured summary, never raw output.

    Round 6 — WS B: a genuinely clean scan and a tool that scanned nothing used to render identically
    (`0 services, 0 findings: no findings` either way), which is what let six of seven sandboxed tools
    report a false "clean" result in production without anyone noticing. Below, `_no_output` and the
    `parsed_ok` check give the model three distinguishable outcomes instead of two: no output at all,
    output that arrived but didn't parse, and a real empty result — the last of which is only
    trustworthy now that it can no longer be produced by the other two. Wording on the first two is
    deliberately pointed: this text is the model's entire basis for its next decision, so it must push
    toward investigating or switching tools, never toward concluding the target is clean."""
    if not step.allowed:
        return f"DENIED by scope guard: {step.reason}. Choose a different in-scope target."
    if step.error:
        return f"tool error: {step.error}"
    if step.note:  # knowledge tools return their answer directly, before any output-byte check below
        return step.note
    exit_code = getattr(step, "exit_code", None)
    code_txt = f"exit={exit_code}" if exit_code is not None else "exit=unknown"
    if _no_output(step):
        return (
            f"NO OUTPUT from this tool run ({code_txt}). It produced zero bytes to analyze — this is "
            "NOT a clean scan and must NOT be reported as \"no findings\". The tool almost certainly "
            "never actually scanned the target (broken invocation, missing writable path, wrong "
            "mode, a dependency that failed silently). Investigate why it produced nothing, or try a "
            "different tool — do not conclude the target is clean from this."
        )
    if not getattr(step, "parsed_ok", True):
        output_bytes = getattr(step, "output_bytes", 0)
        return (
            f"UNPARSEABLE OUTPUT from this tool run ({code_txt}, {output_bytes} bytes received). The "
            "tool produced output but it could not be parsed into results, so this is also NOT "
            "evidence the target is clean — it's a different failure than silence, not a result. "
            "Investigate the raw failure or try a different tool."
        )
    titles = ", ".join(f.title for f in step.findings[:10]) or "no findings"
    return f"{len(step.services)} services, {len(step.findings)} findings: {titles}"


def _abort(emit, result: "AgentResult") -> RunStatus:
    """Round 5 — WS A: the shared shape for however the loop notices an operator abort (top of an
    iteration, or mid tool-call batch) so the transcript reads the same regardless of where it was
    caught. Emitted for nested specialists too — cutting a child short is worth showing in the
    transcript, even though `_set_status` below is a no-op for them (a nested run never owns the
    top-level run's lifecycle)."""
    emit("warning", scope="abort", message="run aborted by operator")
    result.stop_reason = "aborted by operator"
    return RunStatus.aborted


def _range_guidance(seed: str) -> str | None:
    """B2: guidance for a seed target that is a *range*, not a single host.

    Without this, a model faced with "seed target: 10.0.0.0/24" has no reason not to iterate 256
    addresses one nmap call at a time — each a full single-host scan — which burns the whole
    tool-call budget (and, per B2's nmap.py change, would previously also run each of those 256 calls
    at `-Pn --top-ports 1000`, the slow/expensive shape meant for one host) before the run has
    learned anything about the range as a whole. Returns None for a single host (bare IP, hostname,
    or a `/32`-equivalent network), which needs no special-casing.
    """
    try:
        network = ipaddress.ip_network(seed.strip(), strict=False)
    except ValueError:
        return None
    if network.num_addresses <= 1:
        return None
    return (
        f"Seed target {seed} is a range of {network.num_addresses} addresses, not a single host. "
        "Run ONE host-discovery sweep against the whole range first, then work from the hosts it "
        "discovers — do not iterate individual addresses one at a time, that will exhaust the "
        "tool-call budget before you've covered the range. If the sweep finds nothing, say so and "
        "stop rather than retrying variants of the same range."
    )


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
    seed_target: str | None = None,
    specialist_pool: list | None = None,
    nested: bool = False,
    subagent: str | None = None,
    persona=None,
    cancels=None,
) -> AgentResult:
    budget = budget or Budget.from_env()
    result = AgentResult()

    def emit(kind: str, /, **data) -> None:
        # `kind` is positional-only so an event may legitimately carry a `kind` data field (e.g. the
        # ask_user prompt kind) without colliding with this parameter.
        # Presentation-only event stream; a missing/broken sink never affects the run.
        if events is None:
            return
        # A nested specialist stamps every event with its `kind` so the UI can group child activity
        # under the specialist that produced it. The top-level run leaves it unset.
        if subagent is not None:
            data.setdefault("subagent", subagent)
        try:
            events.emit(run.id, engagement.id, kind, **data)
        except Exception:
            pass

    def _set_status(status: RunStatus) -> None:
        # Run-lifecycle state belongs to the top-level run only. A nested specialist must never flip
        # the shared run status (or its terminal `completed` would end the parent's SSE stream early).
        if nested:
            return
        run.status = status
        if db is not None:
            db.set_run_status(run.id, status.value)
        emit("status", status=status.value)

    # Orchestrator mode: the model is offered specialist sub-agents, not raw tools. It delegates,
    # reads summaries, and never touches a sandbox itself.
    orchestrating = specialist_pool is not None
    if orchestrating:
        from .subagents import SPECIALIST_KINDS, run_specialist, specialist_specs
    else:
        SPECIALIST_KINDS = frozenset()

    authorized, gated = _authorized_stages(engagement.scope)
    if not nested:
        emit(
            "plan",
            stages=STAGES,
            authorized_stages=authorized,
            gated_stages=gated,
            seed_target=run.target,
            budget={"max_tool_calls": budget.max_tool_calls, "max_output_tokens": budget.max_output_tokens},
            # Who the operator launched. The chat header reads this on reconnect: the persona picker's
            # own state is local and resets to the default on reload, so without it a replayed Reaper
            # run would render under the wrong name.
            **_persona_fields(persona),
        )
        if not getattr(engagement.scope, "scope_guard_enabled", True):
            # B3: the guard's own bypass (scope.authorize()) is silent by design at the point of each
            # decision — it just returns Allow — so the operator-facing loudness has to live here and
            # in the audit trail, not in the model's tool-call flow. One event per run, right after
            # the plan the operator is already looking at.
            emit(
                "warning",
                scope="scope_guard",
                message="scope guard is DISABLED for this engagement — every target is authorized",
            )

    _set_status(RunStatus.running)
    system_prompt = mission
    # Memory-in: seed the agent with the remembered network map so it builds on prior runs instead of
    # starting blind. This is guidance only — every tool call is still scope-checked, so a remembered
    # host that has fallen out of scope can never be re-authorized by its presence here.
    known_map = _known_map_message(memory, engagement.id)
    seed = seed_target or run.target
    # B2: tell the model up front when the seed is a range, not a single host — see _range_guidance.
    range_notice = _range_guidance(seed)
    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=f"Seed target: {seed}. Begin."),
    ]
    if range_notice:
        messages.insert(1, Message(role="system", content=range_notice))
    if known_map:
        messages.insert(1, Message(role="system", content=known_map))
    # Always offer ask_user alongside the tool set so the agent can reach the operator. In orchestrator
    # mode the "tools" are the authorized specialist sub-agents; otherwise the (possibly narrowed)
    # registry tools, independent of the tool-library selection.
    if orchestrating:
        specs = [*specialist_specs(engagement.scope), ASK_USER_SPEC]
    else:
        specs = [*registry.specs(), ASK_USER_SPEC]

    # Surface a refusal-aware provider's reinforce/fallback transitions into the event stream.
    if hasattr(provider, "on_refusal"):
        provider.on_refusal = lambda data: emit("refusal", **data)

    stop_status = RunStatus.completed
    keep_blocks = env_int("EYE_AGENT_HISTORY_BLOCKS", DEFAULT_HISTORY_BLOCKS, minimum=0)
    # B2: repeat-call guard. (tool, normalized target, intensity) triples already run *this* run_agent
    # invocation — top-level, or one nested specialist call, each gets its own empty set. A model
    # re-running the identical call gets the identical result, so on a wide range this pattern alone
    # can burn the whole tool-call budget without ever learning anything new; a duplicate is refused
    # in `_run_one` before it reaches the sandbox, still counting against the budget (that accounting
    # happens in the loop below, unconditionally, regardless of what `_run_one` did).
    seen_calls: set[tuple[str, str, str]] = set()
    while True:
        # Round 5 — WS A: checked before every LLM call, the cheapest and most frequent point the
        # loop passes through, so an abort requested between tool calls (or while idle) is honoured
        # without waiting for a running batch to finish.
        if cancels is not None and cancels.is_cancelled(run.id):
            stop_status = _abort(emit, result)
            break
        # Roll up old exchanges before resending the conversation, so input tokens stop growing
        # quadratically over a long run. Never splits an assistant tool_use from its tool_result.
        messages = _compact_history(messages, keep_blocks)
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
        result.input_tokens += resp.input_tokens
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
        # Round 5 — WS A: sticky for the rest of this batch once set, so a cancellation noticed
        # partway through a parallel batch skips every remaining call rather than only the one being
        # checked — a model that returned ten parallel calls must not get to run the last nine just
        # because only the first one was checked before the flag flipped.
        cancelled_mid_batch = False
        for tc in resp.tool_calls:
            if cancelled_mid_batch or (cancels is not None and cancels.is_cancelled(run.id)):
                # Same discipline as the budget-exhausted branch below: every skipped tool_use still
                # gets a matching tool_result so the history never goes structurally invalid.
                cancelled_mid_batch = True
                messages.append(Message(role="tool", tool_call_id=tc.id,
                                        content="skipped: run aborted by operator"))
                continue
            if result.tool_calls_used >= budget.max_tool_calls:
                # The budget is checked *inside* the batch: a model that returns ten parallel calls
                # on the last permitted step must not get to execute all ten. Each skipped tool_use
                # still gets a matching tool_result so the history never goes structurally invalid.
                messages.append(Message(role="tool", tool_call_id=tc.id,
                                        content="skipped: the run's tool-call budget was reached"))
                continue
            if tc.name == "ask_user":
                # Interactive step: emit the question, block for the operator's reply, feed it back.
                summary = _ask_user(engagement, run, tc, emit, inbox)
                # The operator may have hit abort while this call sat blocked on the reply —
                # `inbox.wake()` (events.py) makes `wait()` return promptly instead of riding out the
                # ask timeout, but only this check actually reacts to it. Check right away so the run
                # doesn't act on stale guidance before the rest of the batch notices.
                if cancels is not None and cancels.is_cancelled(run.id):
                    cancelled_mid_batch = True
            elif orchestrating and tc.name in SPECIALIST_KINDS:
                # Delegate to a specialist sub-agent that runs in its own isolated context. Its
                # tool-call/token usage is folded back into this run's budget so the tree stays bounded.
                summary = _dispatch_specialist(
                    tc, run_specialist, engagement, run, provider, sandbox, graph, audit, db,
                    context, events, memory, inbox, specialist_pool, budget, result, emit, cancels)
            else:
                summary = _run_one(engagement, run, tc, registry, sandbox, graph, audit, db, result,
                                   context, emit, memory, seen_calls)
            messages.append(Message(role="tool", content=summary, tool_call_id=tc.id))
            result.tool_calls_used += 1

        if cancelled_mid_batch:
            stop_status = _abort(emit, result)
            break
        if result.tool_calls_used >= budget.max_tool_calls:
            result.stop_reason = "tool-call budget reached"
            break
        if result.total_tokens >= budget.max_output_tokens:
            result.stop_reason = "token budget reached"
            break

    _set_status(stop_status)
    return result


def _history_blocks(body: list[Message]) -> list[list[Message]]:
    """Group the non-system history into atomic blocks.

    A `tool` message answers the assistant turn immediately before it, and the provider adapters
    render it as a `tool_result` referencing that turn's `tool_use` id (llm/claude.py, and the
    OpenAI adapter's `tool_call_id`). Dropping one without the other produces a conversation the
    provider API rejects, so the pair is inseparable: every `tool` message is attached to the block
    opened by the preceding non-tool message, and compaction only ever keeps or drops whole blocks.
    A leading `tool` message with no block to attach to is already an orphan and is dropped."""
    blocks: list[list[Message]] = []
    current: list[Message] = []
    for message in body:
        if message.role == "tool":
            if current:
                current.append(message)
            continue  # orphan (cannot happen from this loop) — never re-emitted
        if current:
            blocks.append(current)
        current = [message]
    if current:
        blocks.append(current)
    return blocks


def _rollup(dropped: list[list[Message]]) -> str:
    """One system line standing in for the exchanges that were dropped, so the model keeps a trace
    of what it already did instead of silently losing it."""
    parts: list[str] = []
    for block in dropped:
        for message in block:
            text = (message.content or "").strip().replace("\n", " ")
            if text:
                parts.append(text[:_HISTORY_ENTRY_CHARS])
    return ("Earlier steps (summarized, oldest first): " + "; ".join(parts))[:_HISTORY_SUMMARY_CHARS]


def _compact_history(messages: list[Message], keep_blocks: int) -> list[Message]:
    """Bound the conversation resent on every iteration (B7).

    Preserved unconditionally: every system message (the mission, the known-map seed) and the first
    body turn — the seed user message, which must stay first because Anthropic requires the message
    list to open with a user turn. Everything between it and the last `keep_blocks` exchanges is
    replaced by a single summary system message. Returns the input list unchanged when there is
    nothing to drop, so short runs behave exactly as before."""
    if keep_blocks <= 0:
        return messages
    system = [m for m in messages if m.role == "system"]
    body = [m for m in messages if m.role != "system"]
    blocks = _history_blocks(body)
    if len(blocks) <= keep_blocks + 1:  # +1 for the seed turn, which is never dropped
        return messages
    seed, rest = blocks[0], blocks[1:]
    dropped, kept = rest[:-keep_blocks], rest[-keep_blocks:]
    if not dropped:
        return messages
    out: list[Message] = [*system, Message(role="system", content=_rollup(dropped)), *seed]
    for block in kept:
        out.extend(block)
    return out


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

    timeout = env_int("EYE_AGENT_ASK_TIMEOUT", DEFAULT_ASK_TIMEOUT_SECONDS, minimum=1)
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


def _dispatch_specialist(tc, run_specialist, engagement, run, provider, sandbox, graph, audit, db,
                         context, events, memory, inbox, specialist_pool, budget, result, emit,
                         cancels=None) -> str:
    """Run one specialist sub-agent the orchestrator delegated to. Emits subagent_started/finished
    around a nested run_agent, carves the child's budget from the parent's remaining budget, and folds
    the child's tool-call/token/finding usage back so the whole tree stays inside one run budget.

    `cancels` (round 5 — WS A) is forwarded to the child's own `run_agent` call so an operator abort
    stops a specialist mid-pass too, rather than letting it run out its whole carved-off budget first —
    the child polls the exact same shared flag, it's just a different `run_agent` invocation."""
    from .subagents import SPECIALISTS

    args = tc.arguments or {}
    kind = tc.name
    target = str(args.get("target", "")).strip()
    focus = args.get("focus")
    spec = SPECIALISTS.get(kind)
    stage = spec.stage if spec else kind
    # Persona identity, stamped on every event this dispatch emits so the transcript can render the
    # sub-agent as itself ("💀 Reaper") rather than a bare id. Empty when the roster has no entry for
    # `kind`, in which case the UI falls back to `specialist` — a stale id degrades to the old label.
    who = _persona_fields(spec)
    if not target:
        emit("subagent_finished", specialist=kind, stage=stage, error="missing 'target' argument", **who)
        return f"specialist '{kind}' needs a 'target' argument"

    remaining_calls = budget.max_tool_calls - result.tool_calls_used
    remaining_tokens = budget.max_output_tokens - result.total_tokens
    if remaining_calls <= 0 or remaining_tokens <= 0:
        emit("subagent_finished", specialist=kind, stage=stage, error="run budget exhausted", **who)
        return f"cannot dispatch '{kind}': the run budget is exhausted — summarize and stop"

    emit("subagent_started", specialist=kind, stage=stage, target=target, focus=focus, **who)
    # The provider instance is shared with every specialist, and a nested run_agent rebinds
    # `on_refusal` to its own emitter (which stamps subagent=kind). Without restoring it, this
    # orchestrator's later refusals would be attributed to the last specialist that ran.
    previous_on_refusal = getattr(provider, "on_refusal", None)
    try:
        summary, calls, out_tokens, in_tokens, findings = run_specialist(
            kind, target, focus, engagement=engagement, run=run, provider=provider, sandbox=sandbox,
            graph=graph, audit=audit, db=db, context=context, events=events, memory=memory,
            inbox=inbox, pool=specialist_pool or [], remaining_calls=remaining_calls,
            remaining_tokens=remaining_tokens, cancels=cancels)
    finally:
        if hasattr(provider, "on_refusal"):
            provider.on_refusal = previous_on_refusal
    result.tool_calls_used += calls
    result.output_tokens += out_tokens
    result.input_tokens += in_tokens
    result.findings += findings
    emit("subagent_finished", specialist=kind, stage=stage, summary=summary, findings=findings,
         tool_calls=calls, **who)
    return summary


def _persona_fields(persona) -> dict:
    """The persona identity carried on run/sub-agent events: who is acting, under what label and
    glyph. Presentation only — the roster decides which tools a persona is *offered*, and the scope
    guard plus the signed-scope flags decide what it may actually run. A missing persona yields an
    empty dict rather than placeholder values, so the UI's fallback path stays distinguishable from
    a persona that genuinely has no label."""
    if persona is None:
        return {}
    return {
        "persona": getattr(persona, "id", None),
        "persona_label": getattr(persona, "label", None),
        "glyph": getattr(persona, "glyph", None),
        "accent": getattr(persona, "accent", None),
    }


def _run_one(engagement, run, tc, registry, sandbox, graph, audit, db, result, context, emit, memory,
             seen_calls: set | None = None) -> str:
    """Validate + execute a single tool call the model proposed, returning the summary it will see.
    Emits the presentation events (tool_call / tool_started / finding / tool_finished / memory_delta)
    around the unchanged execute_tool_step spine.

    `seen_calls` is the run's repeat-call guard (B2): a mutable set of `(tool, target, intensity)`
    triples already executed this run_agent invocation. `None` (the default) disables the guard for
    callers that don't track one — every current caller does, so this only exists as a safety default,
    never as a way to silently skip the check.
    """
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

    # Repeat-call guard: the exact same (tool, target, intensity) triple returns the exact same
    # result, so re-running it teaches the model nothing new. On a wide range that pattern alone can
    # exhaust the tool-call budget before the run ever gets past the seed target. Denied *before* the
    # sandbox is touched — no tool_call/tool_started, no execute_tool_step — but the caller still
    # increments result.tool_calls_used for this iteration exactly as it would for any other call, so
    # this cannot be used to dodge the budget, only to avoid wasted work under it.
    call_key = (tool.name, target.lower(), intensity.value)
    if seen_calls is not None and call_key in seen_calls:
        summary = (f"already ran {tool.name} on {target} this run — result unchanged; choose a "
                   "different action or stop")
        emit("tool_finished", tool=tool.name, target=target, stage=stage, summary=summary, repeat=True)
        return summary
    if seen_calls is not None:
        seen_calls.add(call_key)

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
    if _no_output(step):
        # Round 6 — WS B: the model might still summarize its way around a silent-zero result (or
        # the operator might not be reading every tool_finished summary closely), so this needs its
        # own loud, persistent signal independent of the transcript — the same reasoning B3 used for
        # the scope-guard-disabled warning. `warning` is the event kind the chat UI renders as a
        # banner rather than a transient bubble, which is exactly the visibility a tool that exited
        # having scanned nothing needs.
        emit("warning", scope="tool_output", tool=tool.name, target=target, stage=stage,
             exit_code=getattr(step, "exit_code", None),
             message=f"{tool.name} produced no output against {target} "
                     f"(exit={getattr(step, 'exit_code', None)}) — this is NOT a clean result")

    # Memory-out: surface each observed change so the chat shows a live "network changes" feed.
    delta = getattr(step, "memory_delta", None)
    if delta is not None:
        for entry in _delta_events(delta):
            emit("memory_delta", **entry)

    return summary


_DELTA_BUCKETS = ("added", "changed", "removed", "newly_exploitable")


def _delta_events(delta) -> list[dict]:
    """Flatten a MemoryDelta into per-change event payloads. The shape is normalized once, at the
    boundary — MemoryDelta already knows how to render itself, and a plain dict (test sinks) is
    taken as-is — so the buckets below are read one way instead of duck-typed four times."""
    if isinstance(delta, dict):
        data = delta
    elif hasattr(delta, "to_dict"):
        data = delta.to_dict()
    else:  # an unknown shape: read the buckets off the object, never crash the event stream
        data = {name: getattr(delta, name, []) for name in _DELTA_BUCKETS}
    out: list[dict] = []
    buckets = ((name, data.get(name)) for name in _DELTA_BUCKETS)
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
