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
  runEventsUrl,
  type RunEvent,
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

  const esRef = useRef<EventSource | null>(null);
  const lastSeqRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement | null>(null);

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

  // Keep the transcript pinned to the newest message.
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [events.length]);

  function openStream(id: string, after: number) {
    esRef.current?.close();
    const es = new EventSource(runEventsUrl(id, after));
    esRef.current = es;
    es.onmessage = (e) => {
      const ev: RunEvent = JSON.parse(e.data);
      lastSeqRef.current = Math.max(lastSeqRef.current, ev.seq);
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
      const run = await createRun(selected, { target: target.trim(), mode: "agent", objective });
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

  const view = useMemo(() => derive(events), [events]);

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
          <strong>Authorized, controlled use only.</strong> Codename Eye is for ethical security
          research on assets you own or are contracted in writing to test. Every tool call is checked
          against the engagement's signed scope before it runs — the objective below is guidance, not
          authorization, and cannot widen scope.
        </Callout>
      </div>

      <SectionTitle>1 · Objective &amp; scope</SectionTitle>
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
          <button className="btn btn-primary" onClick={onLaunch} disabled={busy || !selected || !target.trim()}>
            Run agent
          </button>
        </div>
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
            Select an engagement (create one on the Network Map page) to enable runs.
          </div>
        )}
      </div>

      <SectionTitle>2 · Pipeline</SectionTitle>
      <div className="card card-pad">
        <div className="pipeline">
          {view.stages.map((stage) => {
            const cls = view.gated.includes(stage)
              ? "gated"
              : stage === view.currentStage
              ? "active"
              : view.stageIndex(stage) < view.currentIndex
              ? "done"
              : "";
            return (
              <div key={stage} className={`stage ${cls}`}>
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

      <SectionTitle
        action={
          <span className="live">
            {view.findingCount} findings · {view.changeCount} changes
          </span>
        }
      >
        Transcript
      </SectionTitle>
      <div className="card chat" ref={scrollRef}>
        {events.length === 0 && (
          <div className="dim" style={{ textAlign: "center", padding: "28px 0", fontSize: 13 }}>
            No run yet — set an objective above and launch the agent to watch it work.
          </div>
        )}
        {events.map((ev) => (
          <Bubble key={ev.seq} ev={ev} />
        ))}
      </div>
    </main>
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

  const statusLabel = terminal ? `run ${lastStatus}` : lastStatus ? "running" : "";

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
  };
}

function Bubble({ ev }: { ev: RunEvent }) {
  const d = ev.data || {};
  switch (ev.kind) {
    case "thinking":
      return (
        <div className="msg reason">
          <span className="who">◍ agent</span>
          <div className="body">{d.text}</div>
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
