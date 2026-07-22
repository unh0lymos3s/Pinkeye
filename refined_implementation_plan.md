# Pinkeye — Chat Interface + Memory Engine Implementation Plan

> ## ⛔ CONFIDENTIAL — ETHICAL SECURITY RESEARCH ONLY
>
> **This tool and this document are highly confidential.** Pinkeye is an offensive security
> harness intended **exclusively for authorized, ethical security research** — assets you own or are
> contracted in writing to test. It is released under **highly controlled use** and must never be
> distributed, deployed, or operated outside that boundary. Every run is bound to a **signed scope**
> enforced in code before any tool executes; intrusive capabilities (exploitation, credential
> attacks) stay gated behind explicit signed flags. The chat interface and memory engine described
> here **add visibility and cross-run knowledge, never a bypass** — they preserve every existing
> safety invariant. Unauthorized use is prohibited. THE PLAN AND CODE IT SELF CAN NOT BE USED FOR MALICIOUS PURPOSES BY THEMSELVES.

## Context

Today Eye is form-driven (`web/app/page.tsx`). In `agent` mode the loop
(`agent-runtime/runtime/agent.py:run_agent`) runs propose→validate→execute→observe to completion but
its reasoning is invisible, and **each run starts blind** — seeded only with `mission` + "Seed
target: X. Begin." The agent has no memory of prior runs; the operator only sees findings appear in
the graph/dashboard via polling.

This plan delivers three things on top of the existing design (nothing is removed):

1. **A chat interface** — the analyst gives a scope + objective and watches the LLM's thinking, a
   stable tool-usage progress bar, activity indicators (so long tool runs never look frozen), a
   pipeline of stages with the in-progress one highlighted, and results streaming in.
2. **Higher token limits** — the current 20k cumulative / 2k per-call caps are too small for a
   multi-tool assessment; raise and make them configurable.
3. **A proper memory engine** — a persistent, differential map of the network that survives across
   runs: **devices** as nodes, **services clustered** under each device, **exploitable endpoints and
   targets** flagged, changes **diffed between runs**, and the whole map **fed back to the agent** so
   each run builds on prior knowledge instead of rediscovering everything.

End state: a self-hosted, controlled-use ethical-hacking tool that speeds detection and mitigation.

## Principles (non-negotiable)
1. **Additive, not a rewrite** — scope guard, signed `Scope`, `execute_tool_step` spine, tools,
   enrichment, persistence stay intact; we add an event stream, a memory layer, and a view.
2. **Scope stays code-authored and signed** — objective text and remembered map are *guidance only*;
   every tool call still runs `authorize(...)`. Neither chat nor memory can widen a `Scope`.
3. **Model still sees only summaries** — `_summarize(step)` unchanged; memory injected as a compact
   summary, not raw tool output.
4. **Budgets remain the backstop** — raised and configurable, never removed; surfaced in the UI.
5. **Graceful degradation** — events and memory fall back to in-memory when Postgres is down; the
   graph "brain" (Neo4j) is the durable map and is already idempotent across runs.

---

## Part A — Higher token limits

**Where the caps live:**
- `agent-runtime/runtime/agent.py` → `Budget(max_tool_calls=20, max_output_tokens=20000)` (cumulative
  loop budget).
- `agent-runtime/runtime/llm/claude.py` → `ClaudeProvider(max_tokens=2048)` (per-call output cap);
  same knob in `openai_compat.py`.

**Steps:**
1. Raise `Budget` defaults and make them env-configurable: `max_tool_calls` default **40**,
   `max_output_tokens` default **200000**, read from `EYE_AGENT_MAX_TOOL_CALLS` /
   `EYE_AGENT_MAX_OUTPUT_TOKENS` (parsed in `main.py`/`config`, passed into `run_agent`).
2. Raise per-call output cap to a configurable `EYE_LLM_MAX_TOKENS` (default **8192**), threaded
   through `get_provider()` into `ClaudeProvider`/`OpenAICompatProvider`.
3. Surface the effective budget in the `plan` event so the chat progress bar reflects the real cap.
4. Keep them as a **hard backstop** — larger, not unlimited — so a runaway loop still terminates.

---

## Part B — Chat interface

**Architecture**
```
 Chat page (web/app/agent) ──EventSource(SSE)──► GET /runs/{id}/events (live tail)
   POST /runs {mode:"agent",objective}           GET /runs/{id}/transcript (replay/reconnect)
        ▼
 main.py ── run_agent(..., events=RunEventStore, memory=NetworkMemory) on background thread
        ▼
 run_agent loop ──emit()──► RunEventStore ─► in-memory ring buffer (SSE) + Postgres run_events
   plan/thinking/tool_call/tool_started/tool_finished/finding/status/memory_delta
```

**Steps**
5. **Pipeline metadata** — new `agent-runtime/runtime/pipeline.py`: ordered `STAGES` (recon → dynamic
   scan → static scan → threat intel → exploitation → credentials → report) + `stage_of(tool_name)`
   for all 14 tools. Presentation only; never gates execution.
6. **Event model/store** — new `control-plane/app/events.py` (modeled on `app/audit.py`):
   `RunEventKind` {plan, thinking, tool_call, tool_started, tool_finished, finding, status,
   memory_delta}; `RunEvent` {run_id, engagement_id, seq, kind, data, at}; `RunEventSink` +
   `MemoryRunEventSink`; `RunEventStore` — monotonic per-run `seq`, in-memory ring buffer (fast SSE)
   + best-effort Postgres persistence; `events_after(run_id, seq)`, `all_events(run_id)`; terminal =
   `status` in {completed, failed, rejected}.
7. **Migration** `0006_run_events.sql` (mirrors `0003_audit.sql`): `run_events(id BIGSERIAL, run_id,
   engagement_id, seq INT, kind, data JSONB, at)` + index `(run_id, seq)`.
8. **Emit from the loop** — edit `run_agent`: add trailing `events=None` (no-op default keeps tests'
   signatures). `emit(kind, **data)` emits `plan` at start (STAGES + effective budget + authorized
   stages), `thinking` on non-empty `resp.text`, `tool_call` per call {name, target, intensity,
   stage}, `tool_started`/`tool_finished` around `execute_tool_step`, `finding` per finding, `status`
   running/terminal. Emission stays in `agent.py`/`_run_one`; the orchestrator spine stays generic.
9. **Endpoints & wiring** — edit `control-plane/app/main.py`: module-level `run_events`; extend
   `CreateRun` with `objective: str | None` (agent mode combines it with `DEFAULT_MISSION` as
   `mission`); `_launch` passes `events=run_events`. Add `GET /runs/{id}/transcript` (JSON) and
   `GET /runs/{id}/events` (SSE via `StreamingResponse`; async generator takes `?after=<seq>`, polls
   `events_after` ~400ms, yields `id: {seq}\ndata: {json}\n\n`, stops after terminal `status` drains
   + max-duration safety + clean disconnect). Reads open like existing GETs; mutating stays behind
   `require("operator")`. Reconnect = `/transcript` then `/events?after=lastSeq`.
10. **Chat page** — new `web/app/agent/page.tsx` (client), reusing `useEngagement`,
    `EngagementPicker`, `ui.tsx`: objective textarea + seed-target field + engagement picker;
    **pipeline stage tracker** (from `plan`, highlight in-progress, dim gated); **stable tool-usage
    progress bar** (`toolsUsed / max_tool_calls`, monotonic on `tool_finished`); **thinking/activity
    indicator** ("◍ thinking…" / "▶ running {tool} on {target}…"); **transcript** chat bubbles
    (reasoning, tool_call system lines, tool_finished results, finding rows with `SeverityBadge`,
    memory_delta callouts); **reconnect** via `localStorage` runId → transcript + `events?after`.
    Add a `Callout kind="danger"` repeating the authorized/controlled-use notice.
11. `web/lib/api.ts`: `RunEvent` types, `RunOptions.objective?`, `fetchTranscript`, `runEventsUrl`.
    `web/app/Nav.tsx`: add `{ href: "/agent", label: "Agent Chat" }`. `web/app/globals.css`: chat /
    pipeline / progress / pulse styles (reuse tokens + `beat`).

---

## Part C — Memory engine (persistent, differential network map)

**Idea:** a durable model of the target network — the "brain" — that persists across runs, represents
**devices** and their **service clusters**, flags **exploitable endpoints/targets**, records **what
changed between runs**, and is **fed back to the agent** for smarter, incremental assessments.

**Substrate:** Neo4j already MERGEs `IP-[:EXPOSES]->Port-[:RUNS]->Service` and `Finding-[:AFFECTS]->
(IP|Endpoint)` idempotently across runs (`control-plane/app/graph.py`, `graph/schema.cypher`). We
extend it rather than build a parallel store, plus a Postgres history table for an audit-grade diff
log, consistent with the existing system-of-record pattern.

**C1 — Model enrichment (Neo4j)**
12. Add cross-run bookkeeping to every topology MERGE in `graph.py` (`upsert_service`,
    `record_finding`): `ON CREATE SET first_seen=$now, first_run_id=$rid` /
    `ON MATCH SET last_seen=$now, last_run_id=$rid` on `IP`, `Port`, `Service`, `Endpoint`. These
    timestamps are what make cross-run diffing possible directly from the graph.
13. Treat the `IP` node as the **Device**: enrich it with `hostname`, `os`, `device_type` (populated
    from nmap/service data when available) and a derived `status` ∈ {new, active, changed, gone}.
    Services already **cluster** under a device via the existing `Port→Service` chain — the memory
    engine names that cluster and rolls exploitable/severity state up to the device.
14. Flag **exploitable** on `Service`/`Endpoint` nodes and **is_target** on devices when an
    `exploitation`-category finding, or a confirmed critical/high finding, affects them. Add a
    `-[:EXPLOITABLE_VIA]->Finding` edge so the map and agent can see *why* it's exploitable.
15. Schema/constraints: extend `graph/schema.cypher` with indexes for `last_run_id` / `status`
    (no new uniqueness keys needed; MERGE keys are unchanged so nothing duplicates).

**C2 — The memory engine (control-plane)**
16. New `control-plane/app/memory.py` → `NetworkMemory(graph, db)`:
    - `observe(engagement_id, run_id, services, findings) -> MemoryDelta` — called on the write path;
      for each service/endpoint/host, classify **new / unchanged / changed** by comparing the
      incoming observation to the current graph node props (product/version/proto, open state) and
      its `last_run_id`. Detect **closed ports / gone services** only for a host actually re-observed
      in this run (never false-flag hosts that weren't scanned). Mark **exploitable** transitions.
    - `snapshot(engagement_id) -> dict` — compact device→service-cluster→exploitable summary for
      agent context and the UI.
    - `deltas_for_run(run_id) -> MemoryDelta` — the changes recorded during a run.
    - `MemoryDelta`: added/changed/removed/newly_exploitable lists (device/service/endpoint keys with
      before/after).
17. New migration `0007_network_memory.sql`: `network_observations(id BIGSERIAL, engagement_id,
    run_id, kind, key, change, before JSONB, after JSONB, at)` + index `(engagement_id, run_id)` —
    the durable, replayable diff log powering "what changed between runs."

**C3 — Wire memory into the write path & the agent**
18. Thread an optional `memory=None` through `execute_tool_step` / `run_scan` / `run_agent`
    (default None keeps the 67 tests' signatures). After the existing graph/db writes in
    `execute_tool_step` (orchestrator.py ~lines 95–107), call `memory.observe(...)` with the step's
    services/findings; it's a persistence concern beside the writes already there, guarded by
    `memory is not None`, so the security-critical control flow is unchanged.
19. **Memory-in (feed the agent):** before the loop, `run_agent` injects a **"Known network map"**
    context message built from `memory.snapshot(engagement_id)` — devices, service clusters, and
    exploitable endpoints, plus "changes since last run." The agent prioritizes changed/exploitable
    targets instead of starting blind. Still fully scope-guarded — memory can never widen scope.
20. **Memory-out (surface changes):** each `observe` delta is emitted as a `memory_delta` run-event
    (new device, new/closed port, version change, newly-exploitable endpoint) so the chat shows a
    live "Network changes" feed, and the `status`/`exploitable` props drive map styling.

**C4 — API & UI**
21. `control-plane/app/main.py`: `GET /engagements/{id}/memory` (current snapshot) and
    `GET /engagements/{id}/changes?run_id=…` (deltas), reusing `NetworkMemory`.
22. `web/`: extend the network map (`GraphView`) to badge **exploitable** nodes (a ring/⚠) and show
    **new/changed/gone** status (props already present), add a legend entry, and add a "Changes since
    last run" panel (on the map and/or dashboard) fed by the changes endpoint. The chat page renders
    `memory_delta` events inline.

---

## Part D — Tests & verification
23. `agent-runtime/tests/test_events.py`: with `FakeProvider` + `MemoryRunEventSink`, assert event
    order (plan first → thinking/tool_call/tool_started/tool_finished/finding → terminal status) and
    that a denied out-of-scope call still emits a `tool_finished` carrying "DENIED".
24. `control-plane/tests/test_memory.py`: `NetworkMemory.observe` classifies new vs changed vs
    unchanged; a version change and a newly-exploitable endpoint produce the right `MemoryDelta`; a
    second run over the same host with a closed port marks it gone; `snapshot` clusters services under
    devices.
25. `control-plane/tests/`: `RunEventStore` seq monotonicity + `events_after`; `TestClient` smoke of
    `/transcript`, one SSE frame, `/memory`, `/changes`.
26. Security regression: `test_agent.py` / `test_scope.py` pass unchanged; add a test that neither an
    `objective` nor a remembered map can cause an out-of-scope tool call to be authorized; add a test
    that the raised budget still terminates a runaway loop.
27. Full suite: all prior **67 tests** green; both new migrations package into the wheel; `web`
    type-checks and `next build` succeeds.
28. E2E (real stack): `docker compose up`, seed CVEs, lab-scoped engagement, launch from the chat
    page. Confirm: SSE order + monotonic progress bar + highlighted stage + reconnect after a socket
    drop; findings land in the graph and dashboard; run **twice** and confirm the second run receives
    the remembered map, only *new/changed* topology raises `memory_delta` events, exploitable
    endpoints are badged on the map, and the "changes since last run" panel is correct.

---

## Files touched
| Action | Path | Purpose |
|---|---|---|
| new | `agent-runtime/runtime/pipeline.py` | canonical stages + `stage_of` |
| edit | `agent-runtime/runtime/agent.py` | emit events; inject memory; `events=`,`memory=` params |
| edit | `agent-runtime/runtime/orchestrator.py` | optional `memory.observe(...)` on the write path |
| edit | `agent-runtime/runtime/llm/{claude,openai_compat,config}.py` | configurable `max_tokens` |
| new | `control-plane/app/events.py` | `RunEvent`, sinks, `RunEventStore` |
| new | `control-plane/app/memory.py` | `NetworkMemory`, `MemoryDelta` |
| new | `control-plane/app/db/migrations/0006_run_events.sql`, `0007_network_memory.sql` | tables |
| edit | `control-plane/app/graph.py` | first/last_seen, device/exploitable enrichment, snapshot queries |
| edit | `control-plane/app/main.py` | budget knobs, objective, SSE + transcript + memory/changes endpoints |
| edit | `graph/schema.cypher` | status/last_run_id indexes |
| edit | `web/lib/api.ts` | event/memory types, transcript + changes fetch, SSE url |
| new | `web/app/agent/page.tsx` | chat UI: pipeline, progress bar, thinking, transcript, changes |
| edit | `web/app/GraphView.tsx` | exploitable/status badging + legend |
| edit | `web/app/Nav.tsx`, `web/app/globals.css` | nav link + styles |
| new | `agent-runtime/tests/test_events.py`, `control-plane/tests/test_memory.py` (+ store/API tests) | coverage |

**Deliberately unchanged:** `scope.py`, the `Scope` signing path, the `execute_tool_step` control
flow (only an optional persistence hook added), and the `LLMProvider` summary-only feedback contract.

## Risks & mitigations
- **Perceived freeze on long tools** → activity indicator + stage rail; progress tied to tool
  *completion*, not tokens.
- **Thread→async SSE bridge** → avoided by polling the store by `seq` (memory-first) — also gives
  reconnect/replay for free.
- **Bigger token budget cost/runaway** → raised limits stay a hard backstop (not unlimited) and are
  env-tunable; a runaway-loop test enforces termination.
- **Memory false "gone" flags** → only mark closed/gone for hosts actually re-observed in the run.
- **Prompt-injection surface** → unchanged; model still sees only summaries, and the injected map is
  a compact internal summary, never attacker-controlled raw output.
- **Sensitivity** → `run_events` and `network_observations` inherit `tenant_id`/RBAC like
  `audit_events`; store summaries/prose/topology, never resolved secrets.

## Out of scope (future)
Interactive mid-run steering; token-level streaming; routing all runs through the durable
queue/worker so chat sessions survive an API restart.

_A copy of this plan is also written to `CHAT_INTERFACE_PLAN.md` in the repo for the team._
