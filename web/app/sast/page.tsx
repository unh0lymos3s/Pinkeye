"use client";
// SAST: upload a codebase (zip / tar / tar.gz) or a single source file, and the harness extracts it,
// authorizes the extracted path in the engagement's signed scope, and runs the static-analysis
// specialist over it — Snyk Code (the SAST slot), gitleaks, and trivy — streaming its work live.
//
// The scan runs as the `sast` agent profile against the uploaded path. Everything here is visibility
// over the same scope-guarded runtime as the rest of the app: uploading is the authorization, and it
// can only ever add a local source path — never a network target or an offensive capability.
import { useEffect, useMemo, useRef, useState } from "react";
import EngagementPicker from "../EngagementPicker";
import { Callout, SectionTitle, SeverityBadge } from "../ui";
import {
  createRun,
  fetchTranscript,
  listTools,
  runEventsUrl,
  uploadSast,
  type RunEvent,
  type SastUpload,
  type Tool,
} from "../../lib/api";
import { useEngagement } from "../../lib/useEngagement";

const RUN_KEY = "eye.sastRunId";
const TERMINAL = new Set(["completed", "failed", "rejected"]);
// SAST tools live on the "static scan" stage. Presentation labels only — the real tool names (left)
// are what the backend runs; `semgrep` is the slot the pooled Snyk Code MCP server backs.
const SAST_TOOLS = ["semgrep", "gitleaks", "trivy"];
const TOOL_LABEL: Record<string, string> = {
  semgrep: "Snyk Code",
  gitleaks: "gitleaks",
  trivy: "trivy",
};
const TOOL_HINT: Record<string, string> = {
  semgrep: "SAST / SCA — code vulnerabilities (Snyk Code when wired, else Semgrep)",
  gitleaks: "hardcoded secrets & credentials",
  trivy: "dependency & container CVEs",
};

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function SastPage() {
  const { engagements, selected, select } = useEngagement();

  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploaded, setUploaded] = useState<SastUpload | null>(null);
  const [error, setError] = useState("");

  const [tools, setTools] = useState<Tool[]>([]);
  const [engines, setEngines] = useState<Set<string>>(new Set(SAST_TOOLS));

  const [runId, setRunId] = useState("");
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");

  const esRef = useRef<EventSource | null>(null);
  const lastSeqRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Which SAST tools are actually registered, and whether the Snyk MCP backend is wired for the slot.
  useEffect(() => {
    listTools()
      .then((t) => setTools(t.filter((x) => SAST_TOOLS.includes(x.name))))
      .catch(() => {});
  }, []);

  // Reconnect to an in-flight scan after a reload.
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

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [events.length]);

  const snykWired = useMemo(() => tools.find((t) => t.name === "semgrep")?.mcp ?? false, [tools]);

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
      es.close();
      if (esRef.current === es) esRef.current = null;
    };
  }

  function pickFile(f: File | null) {
    setFile(f);
    setUploaded(null);
    setError("");
  }

  async function onUpload() {
    if (!selected || !file) return;
    setUploading(true);
    setError("");
    try {
      const res = await uploadSast(selected, file);
      setUploaded(res);
    } catch (e) {
      setError(`upload failed: ${(e as Error).message}`);
    } finally {
      setUploading(false);
    }
  }

  function toggleEngine(name: string) {
    setEngines((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  async function onScan() {
    if (!selected || !uploaded || engines.size === 0) return;
    setBusy(true);
    setStatus("launching static analysis (scope-checked)…");
    setEvents([]);
    lastSeqRef.current = 0;
    const engineList = [...engines];
    const label = engineList.map((n) => TOOL_LABEL[n] ?? n).join(", ");
    try {
      const run = await createRun(selected, {
        target: uploaded.path,
        mode: "agent",
        profile: "sast",
        enabledTools: engineList,
        objective:
          `Statically analyze the uploaded source tree at ${uploaded.path} ` +
          `(${uploaded.file_count} files). Run the enabled static-analysis tools (${label}) against ` +
          `that path and report every vulnerability, hardcoded secret, and vulnerable dependency you find.`,
      });
      setRunId(run.id);
      if (typeof window !== "undefined") localStorage.setItem(RUN_KEY, run.id);
      setStatus(`run ${run.id.slice(0, 8)} — ${run.status}`);
      openStream(run.id, 0);
    } catch (e) {
      setStatus(`error: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  const view = useMemo(() => derive(events), [events]);
  const canScan = !!selected && !!uploaded && engines.size > 0 && !busy;

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Static Analysis (SAST)</h1>
          <p className="page-sub">
            Upload a codebase and the harness extracts it, authorizes it in the engagement scope, and
            runs the static-analysis specialist over it — code vulnerabilities, secrets, and vulnerable
            dependencies — streaming findings live.
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
          <strong>Authorized code only.</strong> Upload source you own or are contracted in writing to
          assess. Uploading a codebase adds its extracted path to the engagement&apos;s signed scope so
          the analyzers may read it (read-only) — it never grants any network or offensive capability.
        </Callout>
      </div>

      <SectionTitle>1 · Engagement &amp; codebase</SectionTitle>
      <div className="card card-pad">
        <div className="row" style={{ alignItems: "flex-end", flexWrap: "wrap" }}>
          <div className="field" style={{ minWidth: 220 }}>
            <label>Active engagement</label>
            <EngagementPicker engagements={engagements} selected={selected} onSelect={select} />
          </div>
        </div>

        <div
          className={`sast-drop${dragOver ? " over" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files?.[0] ?? null;
            if (f) pickFile(f);
          }}
          onClick={() => fileInputRef.current?.click()}
          role="button"
          tabIndex={0}
          style={{ marginTop: 14 }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz"
            style={{ display: "none" }}
            onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
          />
          <div className="sast-drop-icon">⇪</div>
          {file ? (
            <div>
              <div className="mono">{file.name}</div>
              <div className="dim" style={{ fontSize: 12 }}>{humanBytes(file.size)} · click to replace</div>
            </div>
          ) : (
            <div>
              <div>Drop a <b>.zip</b> / <b>.tar</b> / <b>.tar.gz</b> archive here, or a single source file</div>
              <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>or click to browse</div>
            </div>
          )}
        </div>

        <div className="row" style={{ marginTop: 12, alignItems: "center", gap: 12 }}>
          <button
            className="btn btn-primary"
            onClick={onUpload}
            disabled={!selected || !file || uploading}
          >
            {uploading ? "Uploading…" : "Upload & extract"}
          </button>
          {uploaded && (
            <span className="live">
              ✓ extracted {uploaded.file_count} file{uploaded.file_count === 1 ? "" : "s"} ·{" "}
              {humanBytes(uploaded.total_bytes)} · <span className="mono dim">{uploaded.path}</span>
            </span>
          )}
          {error && <span className="err">{error}</span>}
        </div>
        {!selected && (
          <div className="dim" style={{ marginTop: 10, fontSize: 13 }}>
            Select an engagement (create one on the Home page) to upload code.
          </div>
        )}
      </div>

      <SectionTitle>2 · Analyzers</SectionTitle>
      <div className="card card-pad">
        <div className="row" style={{ flexWrap: "wrap", gap: 10 }}>
          {SAST_TOOLS.map((name) => {
            const registered = tools.some((t) => t.name === name);
            const on = engines.has(name);
            const shownLabel =
              name === "semgrep" ? (snykWired ? "Snyk Code" : "Semgrep") : TOOL_LABEL[name];
            return (
              <label
                key={name}
                className={`sast-engine${on ? " on" : ""}${registered ? "" : " missing"}`}
                title={registered ? TOOL_HINT[name] : "not registered on this deployment"}
              >
                <input
                  type="checkbox"
                  checked={on}
                  disabled={!registered}
                  onChange={() => toggleEngine(name)}
                />
                <span className="sast-engine-name">{shownLabel}</span>
                {name === "semgrep" && snykWired && <span className="tag">snyk mcp</span>}
                <span className="dim sast-engine-hint">{TOOL_HINT[name]}</span>
              </label>
            );
          })}
        </div>
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn btn-primary" onClick={onScan} disabled={!canScan}>
            Run static analysis
          </button>
          {!uploaded && (
            <span className="dim" style={{ marginLeft: 12, fontSize: 13, alignSelf: "center" }}>
              Upload a codebase above first.
            </span>
          )}
          {status && (
            <span className="muted" style={{ marginLeft: 12, fontSize: 13, alignSelf: "center" }}>
              {status}
            </span>
          )}
        </div>
      </div>

      <SectionTitle
        action={<span className="live">{view.findingCount} findings · {view.toolsUsed} scans</span>}
      >
        Results
      </SectionTitle>
      <div className="card chat chat-full">
        {events.length === 0 && (
          <div className="dim" style={{ textAlign: "center", padding: "28px 0", fontSize: 13 }}>
            No scan yet — upload a codebase, pick analyzers, and run the static analysis to watch it work.
          </div>
        )}
        {events.map((ev) => (
          <Bubble key={ev.seq} ev={ev} />
        ))}
        <div ref={bottomRef} />
      </div>
    </main>
  );
}

// Derive the compact status/counters from the event stream (pure).
function derive(events: RunEvent[]) {
  const findingCount = events.filter((e) => e.kind === "finding").length;
  const toolsUsed = events.filter((e) => e.kind === "tool_finished").length;
  const statusEvents = events.filter((e) => e.kind === "status");
  const lastStatus = statusEvents[statusEvents.length - 1]?.data?.status || "";
  const terminal = TERMINAL.has(lastStatus);
  const statusLabel = terminal ? `scan ${lastStatus}` : lastStatus ? "scanning" : "";
  return { findingCount, toolsUsed, terminal, status: statusLabel };
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
          <span className="tag">{d.stage}</span> → running <b>{d.tool}</b> on{" "}
          <span className="mono">{d.target}</span>
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
          <div className="body">{d.error ? <span className="err">error: {d.error}</span> : d.summary}</div>
        </div>
      );
    case "finding":
      return (
        <div className="msg finding">
          <SeverityBadge severity={d.severity} />
          <span className="title">{d.title}</span>
          <span className="mono dim">{d.target}</span>
          {d.cve && <span className="tag">{d.cve}</span>}
          {d.cwe && <span className="tag">{d.cwe}</span>}
        </div>
      );
    case "subagent_started":
      return (
        <div className="msg sys subagent-start">
          <span className="who">▼ {d.specialist} specialist</span>
          <div className="body">
            {d.stage && <span className="tag">{d.stage}</span>} on <span className="mono">{d.target}</span>
          </div>
        </div>
      );
    case "subagent_finished":
      return (
        <div className="msg sys subagent-end">
          <span className="who">▲ {d.specialist} specialist done</span>
          <div className="body">{d.summary}</div>
        </div>
      );
    case "error":
      return (
        <div className="msg tool denied">
          <span className="who">✕ {d.scope === "llm" ? "model error" : "run error"}</span>
          <div className="body">{d.message || d.error}</div>
        </div>
      );
    case "status":
      if (TERMINAL.has(d.status)) return <div className="msg sys done-line">— scan {d.status} —</div>;
      return null;
    default:
      return null;
  }
}
