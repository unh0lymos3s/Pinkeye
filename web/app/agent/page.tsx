"use client";
// Agent Chat: give the LLM planner a scope + objective and watch it work — its reasoning, a pipeline
// stage rail, a monotonic tool-usage progress bar, live activity, findings, and cross-run "network
// changes" all stream in over Server-Sent Events. Reconnects to an in-flight run after a reload.
//
// Everything here is read-only visibility over the existing scope-guarded runtime: the objective is
// guidance, never authorization, and every tool call the agent makes is still checked against the
// engagement's signed scope before anything executes.
import { useEffect, useMemo, useRef, useState } from "react";
import EngagementPicker from "../EngagementPicker";
import { Callout, SectionTitle, SeverityBadge } from "../ui";
import {
  createRun,
  fetchTranscript,
  listProfiles,
  listTools,
  runEventsUrl,
  sendReply,
  type Profile,
  type RunEvent,
  type Tool,
} from "../../lib/api";
import { useEngagement } from "../../lib/useEngagement";

const RUN_KEY = "eye.agentRunId";
const FALLBACK_STAGES = [
  "recon",
  "dynamic scan",
  "static scan",
  "threat intel",
  "exploitation",
  "credentials",
  "report",
];
const TERMINAL = new Set(["completed", "failed", "rejected"]);

// Tool -> pipeline stage, mirroring agent-runtime/runtime/pipeline.py (_TOOL_STAGE). Presentation
// only: it lets the tool library group tools by phase and lets the pipeline rail dim stages the
// operator has switched off. Unknown tools fall back to the first stage, matching stage_of().
const TOOL_STAGE: Record<string, string> = {
  nmap: "recon",
  nuclei: "dynamic scan",
  ffuf: "dynamic scan",
  nikto: "dynamic scan",
  zap: "dynamic scan",
  semgrep: "static scan",
  gitleaks: "static scan",
  trivy: "static scan",
  cve_lookup: "threat intel",
  virustotal: "threat intel",
  tls_cert: "threat intel",
  exploit: "exploitation",
  post_exploit: "exploitation",
  credential_attack: "credentials",
};
const stageOf = (tool: string) => TOOL_STAGE[tool] || FALLBACK_STAGES[0];
// "report" is a terminal presentation stage with no tool of its own, so it is always part of the pipeline.
const ALWAYS_STAGES = new Set(["report"]);

export default function AgentChat() {
  const { engagements, selected, select } = useEngagement();
  const [objective, setObjective] = useState(
    "Discover the attack surface of the seed host and identify exploitable services."
  );
  const [target, setTarget] = useState("10.0.0.5");
  const [runId, setRunId] = useState<string>("");
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  // Tool library: the registered tools and the operator's per-run selection. `enabled === null`
  // means "not yet loaded"; once tools arrive we default to every tool checked.
  const [tools, setTools] = useState<Tool[]>([]);
  const [enabled, setEnabled] = useState<Set<string> | null>(null);

  // Agent profile: who drives the assessment. "full" = an orchestrator delegating to specialist
  // sub-agents; a specialist name runs that one focused specialist; "flat" = legacy generalist.
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState("full");

  // Interactive chat: the operator's reply draft while the agent is waiting on an ask_user prompt.
  const [reply, setReply] = useState("");
  const [sending, setSending] = useState(false);

  const esRef = useRef<EventSource | null>(null);
  const lastSeqRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  // Seqs that arrived over the live SSE stream (as opposed to the initial transcript replay on
  // reconnect). Only these get the streaming-reveal treatment — replaying old history should show
  // instantly, not re-animate the whole run.
  const liveSeqsRef = useRef<Set<number>>(new Set());

  // Load the tool library once; default to all tools enabled.
  useEffect(() => {
    listTools()
      .then((t) => {
        setTools(t);
        setEnabled((prev) => prev ?? new Set(t.map((x) => x.name)));
      })
      .catch(() => {});
    listProfiles()
      .then((p) => setProfiles(p.profiles))
      .catch(() => {});
  }, []);

  // Reconnect to an in-flight run after a reload: replay the transcript, then tail from the last seq.
  useEffect(() => {
    const saved = typeof window !== "undefined" ? localStorage.getItem(RUN_KEY) || "" : "";
    if (saved) {
      setRunId(saved);
      fetchTranscript(saved)
        .then((t) => {
          setEvents(t.events);
          lastSeqRef.current = t.events.length ? t.events[t.events.length - 1].seq : 0;
          const last = t.events[t.events.length - 1];
          if (!last || !(last.kind === "status" && TERMINAL.has(last.data?.status))) {
            openStream(saved, lastSeqRef.current);
          }
        })
        .catch(() => {});
    }
    return () => esRef.current?.close();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Keep the transcript pinned to the newest message. The chat is uncapped (the whole run shows as
  // one flowing interface), so we follow a sentinel at the end rather than scrolling an inner box.
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [events.length]);

  // While a "thinking" bubble is still streaming its text in, keep nudging the view along —
  // instant (not smooth) so it doesn't fight the scroll-on-new-message animation above.
  const stickToBottom = () => bottomRef.current?.scrollIntoView({ behavior: "auto", block: "end" });

  function openStream(id: string, after: number) {
    esRef.current?.close();
    const es = new EventSource(runEventsUrl(id, after));
    esRef.current = es;
    es.onmessage = (e) => {
      const ev: RunEvent = JSON.parse(e.data);
      lastSeqRef.current = Math.max(lastSeqRef.current, ev.seq);
      liveSeqsRef.current.add(ev.seq);
      setEvents((prev) => (prev.some((p) => p.seq === ev.seq) ? prev : [...prev, ev]));
      if (ev.kind === "status" && TERMINAL.has(ev.data?.status)) {
        es.close();
        esRef.current = null;
      }
    };
    es.onerror = () => {
      // Socket dropped. Close and, unless the run already ended, resume tailing from the last seq.
      es.close();
      if (esRef.current === es) esRef.current = null;
      setTimeout(() => {
        if (!esRef.current && !isTerminal(latestRef.current)) openStream(id, lastSeqRef.current);
      }, 1500);
    };
  }

  // Keep a ref to the latest events for the reconnect timer (closures capture stale state otherwise).
  const latestRef = useRef<RunEvent[]>([]);
  latestRef.current = events;

  async function onLaunch() {
    if (!selected || !target.trim()) return;
    setBusy(true);
    setStatus("launching agent run (scope-checked)…");
    setEvents([]);
    lastSeqRef.current = 0;
    try {
      const run = await createRun(selected, {
        target: target.trim(),
        mode: "agent",
        objective,
        profile,
        // Omit when everything is selected so the backend treats it as "all tools".
        enabledTools: enabled && enabled.size < tools.length ? [...enabled] : undefined,
      });
      setRunId(run.id);
      if (typeof window !== "undefined") localStorage.setItem(RUN_KEY, run.id);
      setStatus(`run ${run.id.slice(0, 8)} — ${run.status}`);
      openStream(run.id, 0);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  // Send the operator's reply to a waiting ask_user prompt. The backend echoes it back as a
  // `user_reply` event over SSE, so we don't optimistically insert it — we just clear the draft.
  async function submitReply(text: string) {
    const t = text.trim();
    if (!t || !runId || sending) return;
    setSending(true);
    try {
      await sendReply(runId, t);
      setReply("");
    } catch (e) {
      setStatus(`reply failed: ${String(e)}`);
    } finally {
      setSending(false);
    }
  }

  const view = useMemo(() => derive(events), [events]);

  const activeProfile = useMemo(() => profiles.find((p) => p.name === profile), [profiles, profile]);

  // Stages the current tool selection keeps "on": a stage is live if at least one of its tools is
  // enabled (plus the always-on terminal stages). Used to dim deselected phases on the pipeline rail
  // so it visibly reflects the tool library — both before launch and during the run. A single-
  // specialist profile pins the rail to that specialist's stage so it reflects the chosen profile.
  const enabledStages = useMemo(() => {
    if (activeProfile?.stage) return new Set<string>([...ALWAYS_STAGES, activeProfile.stage]);
    if (!enabled) return new Set(view.stages); // library not loaded yet: assume all on
    const on = new Set<string>(ALWAYS_STAGES);
    for (const name of enabled) on.add(stageOf(name));
    return on;
  }, [enabled, view.stages, activeProfile]);

  const totalTools = tools.length;
  const enabledCount = enabled ? enabled.size : totalTools;

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Agent Chat</h1>
          <p className="page-sub">
            Set an objective and watch the planner reason, choose tools, and stream findings. Cross-run
            memory feeds the agent what it already knows so each run builds on the last.
          </p>
        </div>
        {view.status && (
          <span className="live">
            {!view.terminal && <span className="beat" />}
            {view.status}
          </span>
        )}
      </div>

      <div style={{ margin: "18px 0" }}>
        <Callout kind="danger">
          <strong>Authorized, controlled use only.</strong> Pinkeye is for ethical security
          research on assets you own or are contracted in writing to test. Every tool call is checked
          against the engagement's signed scope before it runs — the objective below is guidance, not
          authorization, and cannot widen scope.
        </Callout>
      </div>

      <SectionTitle>Objective &amp; scope</SectionTitle>
      <div className="card card-pad">
        <div className="row" style={{ alignItems: "flex-end" }}>
          <div className="field" style={{ minWidth: 200 }}>
            <label>Active engagement</label>
            <EngagementPicker engagements={engagements} selected={selected} onSelect={select} />
          </div>
          <div className="field" style={{ minWidth: 180 }}>
            <label>Seed target (IP / host / URL)</label>
            <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.0.0.5" />
          </div>
          <div className="field" style={{ minWidth: 160 }}>
            <label>Agent profile</label>
            <select className="input" value={profile} onChange={(e) => setProfile(e.target.value)}>
              {profiles.length === 0 && <option value="full">full</option>}
              {profiles.map((p) => (
                <option key={p.name} value={p.name} title={p.description}>
                  {p.name}
                  {p.gated_flag ? " · scope-gated" : ""}
                </option>
              ))}
            </select>
          </div>
          <div className="field" style={{ minWidth: 180 }}>
            <label>Tools</label>
            <ToolLibrary
              tools={tools}
              enabled={enabled}
              onChange={setEnabled}
            />
          </div>
          <button className="btn btn-primary" onClick={onLaunch} disabled={busy || !selected || !target.trim()}>
            Run agent
          </button>
        </div>
        {activeProfile && (
          <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
            <b>{activeProfile.name}</b> — {activeProfile.description}
          </div>
        )}
        <div className="field" style={{ marginTop: 12 }}>
          <label>Objective</label>
          <textarea
            className="textarea"
            rows={2}
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="What should the agent focus on? (guidance only)"
          />
        </div>
        {status && <div className="muted" style={{ marginTop: 10, fontSize: 13 }}>{status}</div>}
        {!selected && (
          <div className="dim" style={{ marginTop: 10, fontSize: 13 }}>
            Select an engagement (create one on the Home page) to enable runs.
          </div>
        )}
      </div>

      <SectionTitle
        action={
          totalTools > 0 && (
            <span className="live">
              {enabledCount}/{totalTools} tools enabled
            </span>
          )
        }
      >
        Pipeline
      </SectionTitle>
      <div className="card card-pad">
        <div className="pipeline">
          {view.stages.map((stage) => {
            // Precedence: scope-gated (hard off) → operator-skipped via tool library → run progress.
            const cls = view.gated.includes(stage)
              ? "gated"
              : !enabledStages.has(stage)
              ? "skipped"
              : stage === view.currentStage
              ? "active"
              : view.stageIndex(stage) < view.currentIndex
              ? "done"
              : "";
            const title =
              cls === "gated"
                ? "Gated — the engagement scope does not grant this stage's flag"
                : cls === "skipped"
                ? "Off — no tools for this stage are enabled in the tool library"
                : undefined;
            return (
              <div key={stage} className={`stage ${cls}`} title={title}>
                <span className="dot" />
                {stage}
              </div>
            );
          })}
        </div>
        <div className="progress-wrap">
          <div className="progress-label">
            <span>Tool usage</span>
            <span className="mono">
              {view.toolsUsed} / {view.budgetMax}
            </span>
          </div>
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${Math.min(100, (view.toolsUsed / view.budgetMax) * 100)}%` }} />
          </div>
        </div>
        {view.activity && (
          <div className="activity">
            <span className="pulse" />
            {view.activity}
          </div>
        )}
      </div>

      <div className="chat-shell" style={{ marginTop: 30 }}>
        {(view.findingCount > 0 || view.changeCount > 0) && (
          <div className="chat-shell-head">
            <span className="live">
              {view.findingCount} findings · {view.changeCount} changes
            </span>
          </div>
        )}
        <div className="chat chat-full" ref={scrollRef}>
          {events.length === 0 && (
            <div className="dim" style={{ textAlign: "center", padding: "28px 0", fontSize: 13 }}>
              No run yet — set an objective above and launch the agent to watch it work.
            </div>
          )}
          {events.map((ev) =>
            // Events a specialist sub-agent produced carry a `subagent` label; nest them under the
            // subagent_started header so a delegated pass reads as one indented group.
            ev.data?.subagent ? (
              <div key={ev.seq} className="nested-sub">
                <Bubble ev={ev} live={liveSeqsRef.current.has(ev.seq)} onReveal={stickToBottom} />
              </div>
            ) : (
              <Bubble key={ev.seq} ev={ev} live={liveSeqsRef.current.has(ev.seq)} onReveal={stickToBottom} />
            )
          )}
          <div ref={bottomRef} />
        </div>

        <Composer
          pendingAsk={view.pendingAsk}
          reply={reply}
          setReply={setReply}
          sending={sending}
          onSend={submitReply}
          hasRun={!!runId}
        />
      </div>
    </main>
  );
}

// The chat's reverse channel: a reply box the operator uses to answer the agent's ask_user prompts.
// It lights up while a prompt is pending, and offers Approve/Deny shortcuts for permission requests.
function Composer({
  pendingAsk,
  reply,
  setReply,
  sending,
  onSend,
  hasRun,
}: {
  pendingAsk: RunEvent | null;
  reply: string;
  setReply: (v: string) => void;
  sending: boolean;
  onSend: (text: string) => void;
  hasRun: boolean;
}) {
  const waiting = !!pendingAsk;
  const kind = pendingAsk?.data?.kind || "question";
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Focus the box as soon as the agent asks, so the operator can just start typing.
  useEffect(() => {
    if (waiting) inputRef.current?.focus();
  }, [waiting, pendingAsk?.seq]);

  if (!hasRun) return null;

  const placeholder = waiting
    ? kind === "permission"
      ? "Approve or deny — or type an instruction…"
      : "Type your reply to the agent…"
    : "The agent will prompt you here when it needs a decision.";

  return (
    <div className={`composer${waiting ? " active" : ""}`}>
      {waiting && (
        <div className="composer-head">
          <span className="beat" />
          the agent is waiting on your {kind === "permission" ? "approval" : "reply"}
        </div>
      )}
      <div className="composer-row">
        <input
          ref={inputRef}
          className="input"
          style={{ flex: 1 }}
          value={reply}
          disabled={!waiting || sending}
          placeholder={placeholder}
          onChange={(e) => setReply(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              onSend(reply);
            }
          }}
        />
        {waiting && kind === "permission" && (
          <>
            <button className="btn" onClick={() => onSend("Approved — proceed.")} disabled={sending}>
              ✓ Approve
            </button>
            <button className="btn" onClick={() => onSend("Denied — do not run that. Continue with non-intrusive steps.")} disabled={sending}>
              ✕ Deny
            </button>
          </>
        )}
        <button className="btn btn-primary" onClick={() => onSend(reply)} disabled={!waiting || sending || !reply.trim()}>
          {sending ? "Sending…" : "Send"}
        </button>
      </div>
    </div>
  );
}

// The "tool library": a dropdown of every registered tool, grouped by pipeline stage, that the
// operator checks/unchecks to decide which tools the planner may use this run. Purely a capability
// restriction — deselecting a tool means it is never offered; the scope guard/flag gate still apply.
function ToolLibrary({
  tools,
  enabled,
  onChange,
}: {
  tools: Tool[];
  enabled: Set<string> | null;
  onChange: (next: Set<string>) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  // Close on outside click or Esc while open.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const sel = enabled ?? new Set(tools.map((t) => t.name));
  const total = tools.length;
  const count = sel.size;

  // Group tools by pipeline stage in canonical order; drop stages with no tools (e.g. "report").
  const groups = FALLBACK_STAGES.map((stage) => ({
    stage,
    items: tools.filter((t) => stageOf(t.name) === stage),
  })).filter((g) => g.items.length > 0);

  const toggle = (name: string) => {
    const next = new Set(sel);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    onChange(next);
  };
  const selectAll = () => onChange(new Set(tools.map((t) => t.name)));
  const selectNone = () => onChange(new Set());

  const label =
    total === 0
      ? "loading…"
      : count === total
      ? `All tools · ${total}`
      : count === 0
      ? "No tools selected"
      : `${count} of ${total} tools`;

  return (
    <div className="tool-lib" ref={ref}>
      <button
        type="button"
        className="tool-lib-trigger"
        onClick={() => setOpen((o) => !o)}
        disabled={total === 0}
        aria-expanded={open}
      >
        <span>{label}</span>
        <span className="dim" aria-hidden>
          ▾
        </span>
      </button>
      {open && (
        <div className="tool-menu">
          <div className="tool-menu-head">
            <span className="dim">Enable tools for this run</span>
            <span className="row" style={{ gap: 6 }}>
              <button type="button" className="mini-btn" onClick={selectAll}>
                All
              </button>
              <button type="button" className="mini-btn" onClick={selectNone}>
                None
              </button>
            </span>
          </div>
          <div className="tool-menu-body">
            {groups.map((g) => (
              <div className="tool-group" key={g.stage}>
                <div className="tool-group-title">{g.stage}</div>
                {g.items.map((t) => (
                  <label className="tool-row" key={t.name} title={t.description}>
                    <input type="checkbox" checked={sel.has(t.name)} onChange={() => toggle(t.name)} />
                    <span className="mono tool-name">{t.name}</span>
                    {t.requires_flag && <span className="tag tool-flag">scope-gated</span>}
                    {t.mcp && <span className="tag">mcp</span>}
                  </label>
                ))}
              </div>
            ))}
          </div>
          {count === 0 && (
            <div className="tool-menu-foot dim">No tools selected — the run would fall back to all tools.</div>
          )}
        </div>
      )}
    </div>
  );
}

function isTerminal(events: RunEvent[]): boolean {
  const last = [...events].reverse().find((e) => e.kind === "status");
  return !!last && TERMINAL.has(last.data?.status);
}

// Derive all display state from the ordered event list — pure, so the UI is a function of the stream.
function derive(events: RunEvent[]) {
  const plan = events.find((e) => e.kind === "plan");
  const stages: string[] = plan?.data?.stages || FALLBACK_STAGES;
  const gated: string[] = plan?.data?.gated_stages || [];
  const budgetMax: number = plan?.data?.budget?.max_tool_calls || 40;

  const finished = events.filter((e) => e.kind === "tool_finished");
  const toolsUsed = finished.length;
  const findingCount = events.filter((e) => e.kind === "finding").length;
  const changeCount = events.filter((e) => e.kind === "memory_delta").length;

  const statusEvents = events.filter((e) => e.kind === "status");
  const lastStatus = statusEvents[statusEvents.length - 1]?.data?.status || "";
  const terminal = TERMINAL.has(lastStatus);

  const stageEvents = events.filter((e) => e.data?.stage);
  let currentStage = stageEvents[stageEvents.length - 1]?.data?.stage || stages[0];
  if (terminal) currentStage = "report";
  const stageIndex = (s: string) => stages.indexOf(s);
  const currentIndex = stageIndex(currentStage);

  const lastStarted = Math.max(0, ...events.filter((e) => e.kind === "tool_started").map((e) => e.seq));
  const lastFinished = Math.max(0, ...finished.map((e) => e.seq));
  const running = !terminal && lastStarted > lastFinished;
  const runningEv = running
    ? [...events].reverse().find((e) => e.kind === "tool_started")
    : undefined;
  const last = events[events.length - 1];
  const thinking = !terminal && !running && last?.kind === "thinking";

  let activity = "";
  if (running && runningEv) activity = `▶ running ${runningEv.data.tool} on ${runningEv.data.target}…`;
  else if (thinking) activity = "◍ thinking…";

  // Interactive: an ask_user prompt is "pending" while it has no reply after it and the run is live.
  const askEvents = events.filter((e) => e.kind === "ask");
  const replyEvents = events.filter((e) => e.kind === "user_reply");
  const lastAsk = askEvents[askEvents.length - 1];
  const lastReplySeq = replyEvents.length ? replyEvents[replyEvents.length - 1].seq : 0;
  const pendingAsk = lastAsk && lastAsk.seq > lastReplySeq && !terminal ? lastAsk : null;

  const statusLabel = terminal
    ? `run ${lastStatus}`
    : pendingAsk
    ? "awaiting your input"
    : lastStatus
    ? "running"
    : "";
  if (pendingAsk && !activity) activity = "◍ waiting for your reply…";

  return {
    stages,
    gated,
    budgetMax,
    toolsUsed,
    findingCount,
    changeCount,
    terminal,
    currentStage,
    currentIndex,
    stageIndex,
    activity,
    status: statusLabel,
    pendingAsk,
  };
}

// Simulated token-stream reveal for a "thinking" bubble: the backend's LLM call is blocking and
// hands back the full text in one event (agent-runtime has no token-level streaming today), so we
// fake the live-generation feel client-side by revealing it word-by-word. Only bubbles that arrived
// over the live SSE stream animate — a reconnect's transcript replay renders instantly, since
// re-typing an entire past run on every reload would be slow and wouldn't read as "live" anyway.
function StreamingThinkingText({
  text,
  animate,
  onReveal,
}: {
  text: string;
  animate: boolean;
  onReveal?: () => void;
}) {
  // Keep whitespace as its own tokens so re-joining the revealed slice reproduces the text exactly.
  const words = useMemo(() => text.split(/(\s+)/), [text]);
  const [count, setCount] = useState(animate ? 0 : words.length);

  useEffect(() => {
    if (!animate) return;
    // Scale how many words land per tick so a very long thought still finishes in a couple of
    // seconds instead of visibly crawling, while a short one still reads as a real typewriter.
    const chunk = Math.max(1, Math.ceil(words.length / 150));
    const id = setInterval(() => {
      setCount((c) => {
        const next = Math.min(words.length, c + chunk);
        if (next >= words.length) clearInterval(id);
        return next;
      });
      onReveal?.();
    }, 28);
    return () => clearInterval(id);
    // Runs once per mount: this bubble's seq (and therefore its React key) never changes, so the
    // text/animate props are effectively fixed for its lifetime.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const streaming = animate && count < words.length;
  return (
    <div className="body">
      {words.slice(0, count).join("")}
      {streaming && <span className="stream-caret" />}
    </div>
  );
}

function Bubble({ ev, live, onReveal }: { ev: RunEvent; live: boolean; onReveal?: () => void }) {
  const d = ev.data || {};
  switch (ev.kind) {
    case "plan": {
      const stages: string[] = d.stages || [];
      const gated: string[] = d.gated_stages || [];
      const budget = d.budget?.max_tool_calls;
      return (
        <div className="msg sys plan-msg">
          <span className="who">▚ plan</span>
          <div className="body">
            pipeline:{" "}
            {stages.map((s, i) => (
              <span key={s}>
                {i > 0 && <span className="dim"> › </span>}
                <span className={gated.includes(s) ? "dim" : undefined}>{s}</span>
              </span>
            ))}
            {budget != null && <span className="dim"> · budget {budget} tool calls</span>}
            {gated.length > 0 && (
              <span className="dim"> · gated by scope: {gated.join(", ")}</span>
            )}
          </div>
        </div>
      );
    }
    case "thinking":
      return (
        <div className="msg reason">
          <span className="who">◍ agent</span>
          <StreamingThinkingText text={d.text} animate={live} onReveal={onReveal} />
        </div>
      );
    case "tool_call":
      return (
        <div className="msg sys">
          <span className="tag">{d.stage}</span>
          → calling <b>{d.tool}</b> on <span className="mono">{d.target}</span>
          {d.intensity && <span className="dim"> · {d.intensity}</span>}
        </div>
      );
    case "tool_finished":
      if (d.denied)
        return (
          <div className="msg tool denied">
            <span className="who">⛔ {d.tool} — denied by scope guard</span>
            <div className="body">{d.summary}</div>
          </div>
        );
      return (
        <div className="msg tool">
          <span className="who">✓ {d.tool}</span>
          <div className="body">
            {d.error ? <span className="err">error: {d.error}</span> : d.summary}
          </div>
        </div>
      );
    case "finding":
      return (
        <div className="msg finding">
          <SeverityBadge severity={d.severity} />
          <span className="title">{d.title}</span>
          <span className="mono dim">{d.target}</span>
          {d.cve && <span className="tag">{d.cve}</span>}
        </div>
      );
    case "memory_delta":
      return (
        <div className="msg change">
          <span className="who">
            {d.change === "newly_exploitable" ? "⚠ exploitable" : `Δ ${d.change}`}
          </span>
          <div className="body">{d.label || d.key}</div>
        </div>
      );
    case "ask": {
      const kind = d.kind || "question";
      const glyph = kind === "permission" ? "🔒" : kind === "recommendation" ? "💡" : "❔";
      return (
        <div className={`msg ask ask-${kind}`}>
          <span className="who">
            {glyph} agent needs you · {kind}
          </span>
          <div className="body">{d.question}</div>
          {d.action && (
            <div className="ask-action">
              proposed action: <span className="mono">{d.action}</span>
            </div>
          )}
        </div>
      );
    }
    case "user_reply":
      return (
        <div className={`msg user-reply${d.auto ? " auto" : ""}`}>
          <span className="who">{d.auto ? "⏱ no reply" : "🧑 you"}</span>
          <div className="body">{d.text}</div>
        </div>
      );
    case "subagent_started":
      return (
        <div className="msg sys subagent-start">
          <span className="who">▼ {d.specialist} specialist</span>
          <div className="body">
            {d.stage && <span className="tag">{d.stage}</span>} on <span className="mono">{d.target}</span>
            {d.focus && <span className="dim"> · focus: {d.focus}</span>}
          </div>
        </div>
      );
    case "subagent_finished":
      if (d.error)
        return (
          <div className="msg tool denied">
            <span className="who">✕ {d.specialist} specialist</span>
            <div className="body">{d.error}</div>
          </div>
        );
      return (
        <div className="msg sys subagent-end">
          <span className="who">▲ {d.specialist} specialist done</span>
          <div className="body">
            {d.summary}
            <span className="dim">
              {" "}
              · {d.findings ?? 0} findings · {d.tool_calls ?? 0} calls
            </span>
          </div>
        </div>
      );
    case "refusal": {
      const label =
        d.stage === "reinforce"
          ? "model declined — re-asserting authorization"
          : d.stage === "fallback"
          ? "model declined — routing to fallback model"
          : "model declined the authorized step";
      return (
        <div className="msg sys refusal">
          <span className="who">↺ {label}</span>
          {d.text && <div className="body dim">{d.text}</div>}
        </div>
      );
    }
    case "error":
      return (
        <div className="msg tool denied">
          <span className="who">✕ {d.scope === "llm" ? "model error" : "run error"}</span>
          <div className="body">{d.message || d.error}</div>
        </div>
      );
    case "status":
      if (TERMINAL.has(d.status))
        return <div className="msg sys done-line">— run {d.status} —</div>;
      return null;
    default:
      return null;
  }
}
