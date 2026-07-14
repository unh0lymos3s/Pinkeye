"use client";
// Network map: create a scoped engagement, launch a scan or agent run, and watch the
// persisted knowledge graph fill in. Toggle "full map" for a cross-engagement overview.
import { useEffect, useState } from "react";
import GraphView from "./GraphView";
import EngagementPicker from "./EngagementPicker";
import { Callout, SectionTitle } from "./ui";
import {
  createEngagement,
  createRun,
  fetchChanges,
  fetchGraph,
  fetchMap,
  type Graph,
  type MemoryChanges,
} from "../lib/api";
import { useEngagement } from "../lib/useEngagement";

// Deterministic single-tool scans the map view offers directly. Agent mode ignores this.
const SCAN_TOOLS = ["nmap", "nikto", "nuclei", "ffuf", "tls_cert", "cve_lookup"];
const INTENSITIES = ["light", "normal", "aggressive"];

export default function Home() {
  const { engagements, selected, select, refresh } = useEngagement();
  const [name, setName] = useState("lab-engagement");
  const [cidrs, setCidrs] = useState("10.0.0.0/24");
  const [target, setTarget] = useState("10.0.0.5");
  const [mode, setMode] = useState<"scan" | "agent">("scan");
  const [tool, setTool] = useState("nmap");
  const [intensity, setIntensity] = useState("light");
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] });
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [full, setFull] = useState(false);
  const [lastRunId, setLastRunId] = useState("");
  const [changes, setChanges] = useState<MemoryChanges | null>(null);
  const [fullscreen, setFullscreen] = useState(false);

  // Fullscreen map: exit on Esc, and lock body scroll while the overlay is up.
  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFullscreen(false);
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [fullscreen]);

  // Poll the graph so new findings appear as scans land. Source depends on the "full map" toggle.
  useEffect(() => {
    const tick = () => {
      const p = full ? fetchMap() : selected ? fetchGraph(selected) : Promise.resolve({ nodes: [], edges: [] });
      p.then(setGraph).catch(() => {});
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => clearInterval(t);
  }, [selected, full]);

  // Poll the cross-run memory diff for the most recent run so "what changed since last run" fills in
  // as the run's observations land. Cleared whenever the engagement or tracked run changes.
  useEffect(() => {
    if (!selected || !lastRunId) {
      setChanges(null);
      return;
    }
    const tick = () => {
      fetchChanges(selected, lastRunId).then(setChanges).catch(() => {});
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => clearInterval(t);
  }, [selected, lastRunId]);

  async function onCreate() {
    if (!name.trim()) return;
    setBusy(true);
    setStatus("creating engagement…");
    try {
      const eng = await createEngagement({
        name: name.trim(),
        allowed_cidrs: cidrs.split(",").map((s) => s.trim()).filter(Boolean),
        allowed_domains: [],
      });
      await refresh();
      select(eng.id);
      setStatus(`engagement “${eng.name}” created`);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  async function onScan() {
    if (!selected) return;
    setBusy(true);
    setStatus(mode === "agent" ? "launching agent run (scope-checked)…" : "launching scan (scope-checked)…");
    try {
      const run = await createRun(selected, { target, tool, intensity, mode });
      setLastRunId(run.id);
      setStatus(`run ${run.id.slice(0, 8)} — ${run.status}`);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  const nodeCount = graph.nodes.length;
  const edgeCount = graph.edges.length;

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Network Map</h1>
          <p className="page-sub">
            Create a scoped engagement, launch a scan, and watch the persisted knowledge graph fill in as
            hosts, ports, services, and findings are discovered.
          </p>
        </div>
        <label className="live" style={{ cursor: "pointer" }}>
          <input type="checkbox" checked={full} onChange={(e) => setFull(e.target.checked)} />
          full map (all engagements)
        </label>
      </div>

      <div style={{ margin: "18px 0" }}>
        <Callout kind="warn">
          <strong>Authorized use only.</strong> Every run is checked against the engagement's signed scope
          before any tool executes. Only scan assets you own or are contracted to test.
        </Callout>
      </div>

      <SectionTitle>1 · Engagement</SectionTitle>
      <div className="card card-pad">
        <div className="row" style={{ alignItems: "flex-end" }}>
          <div className="field" style={{ minWidth: 200 }}>
            <label>Active engagement</label>
            <EngagementPicker engagements={engagements} selected={selected} onSelect={select} />
          </div>
          <div className="field" style={{ flex: 1, minWidth: 180 }}>
            <label>New engagement name</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="lab-engagement" />
          </div>
          <div className="field" style={{ flex: 1, minWidth: 180 }}>
            <label>Allowed CIDRs (comma-separated)</label>
            <input className="input" value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="10.0.0.0/24" />
          </div>
          <button className="btn" onClick={onCreate} disabled={busy || !name.trim()}>
            Create
          </button>
        </div>
      </div>

      <SectionTitle>2 · Launch a run</SectionTitle>
      <div className="card card-pad">
        <div className="row" style={{ alignItems: "flex-end" }}>
          <div className="field" style={{ flex: 1, minWidth: 200 }}>
            <label>Target (IP / host / URL)</label>
            <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.0.0.5" />
          </div>
          <div className="field" style={{ minWidth: 150 }}>
            <label>Mode</label>
            <select className="select" value={mode} onChange={(e) => setMode(e.target.value as "scan" | "agent")}>
              <option value="scan">Scan — one tool</option>
              <option value="agent">Agent — LLM plans</option>
            </select>
          </div>
          {mode === "scan" && (
            <>
              <div className="field" style={{ minWidth: 140 }}>
                <label>Tool</label>
                <select className="select" value={tool} onChange={(e) => setTool(e.target.value)}>
                  {SCAN_TOOLS.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              <div className="field" style={{ minWidth: 130 }}>
                <label>Intensity</label>
                <select className="select" value={intensity} onChange={(e) => setIntensity(e.target.value)}>
                  {INTENSITIES.map((i) => (
                    <option key={i} value={i}>{i}</option>
                  ))}
                </select>
              </div>
            </>
          )}
          <button className="btn btn-primary" onClick={onScan} disabled={busy || !selected}>
            {mode === "agent" ? "Run agent" : `Run ${tool}`}
          </button>
        </div>
        {status && (
          <div className="muted" style={{ marginTop: 12, fontSize: 13 }}>
            {status}
          </div>
        )}
        {!selected && (
          <div className="dim" style={{ marginTop: 12, fontSize: 13 }}>
            Select or create an engagement above to enable runs.
          </div>
        )}
      </div>

      <SectionTitle
        action={
          <span className="live">
            {nodeCount > 0 && <span className="beat" />}
            {nodeCount} nodes · {edgeCount} edges
            <button
              className="mini-btn"
              onClick={() => setFullscreen(true)}
              title="Expand the map to fill the screen"
            >
              ⤢ Fullscreen
            </button>
          </span>
        }
      >
        Knowledge graph
      </SectionTitle>
      <div className={`card graph-card${fullscreen ? " graph-fullscreen" : ""}`} style={{ padding: 12 }}>
        {fullscreen && (
          <button className="mini-btn graph-fs-exit" onClick={() => setFullscreen(false)}>
            ✕ Exit fullscreen (Esc)
          </button>
        )}
        <div className="legend" style={{ padding: "4px 6px 12px" }}>
          {[
            ["Engagement", "var(--node-engagement)"],
            ["IP / Host", "var(--node-ip)"],
            ["Port", "var(--node-port)"],
            ["Service", "var(--node-service)"],
            ["Finding", "var(--node-finding)"],
          ].map(([label, color]) => (
            <span className="item" key={label}>
              <span className="swatch" style={{ background: color }} />
              {label}
            </span>
          ))}
          {/* Cross-run memory badges rendered as rings by GraphView. */}
          {[
            ["⚠ exploitable", "#ffb020"],
            ["new", "#34e57a"],
            ["changed", "#ffb020"],
            ["gone", "#5f7a66"],
          ].map(([label, color]) => (
            <span className="item" key={label}>
              <span
                className="swatch"
                style={{ background: "transparent", boxShadow: `inset 0 0 0 2px ${color}` }}
              />
              {label}
            </span>
          ))}
        </div>
        <GraphView graph={graph} fill={fullscreen} />
        {nodeCount === 0 ? (
          <div className="dim" style={{ textAlign: "center", padding: "12px 0 4px", fontSize: 13 }}>
            No graph data yet — launch a run to populate hosts, ports, services, and findings.
          </div>
        ) : (
          <div className="dim" style={{ textAlign: "center", padding: "8px 0 2px", fontSize: 11.5 }}>
            drag to pan · scroll to zoom · double-click to reset
          </div>
        )}
      </div>

      {lastRunId && <ChangesPanel changes={changes} />}
    </main>
  );
}

// The cross-run memory diff for the most recent run: new/changed/gone topology and newly-exploitable
// targets, so an operator sees at a glance what this run added over prior knowledge. Fed by the
// /changes endpoint; the same deltas the agent chat surfaces inline.
function ChangesPanel({ changes }: { changes: MemoryChanges | null }) {
  const groups: [string, string, MemoryChanges["added"]][] = changes
    ? [
        ["Newly exploitable", "danger", changes.newly_exploitable],
        ["New", "new", changes.added],
        ["Changed", "changed", changes.changed],
        ["Gone", "gone", changes.removed],
      ]
    : [];
  const total = groups.reduce((n, [, , items]) => n + items.length, 0);
  return (
    <>
      <SectionTitle
        action={
          <span className="live">
            {total > 0 && <span className="beat" />}
            {total} change{total === 1 ? "" : "s"}
          </span>
        }
      >
        Changes since last run
      </SectionTitle>
      <div className="card card-pad">
        {total === 0 ? (
          <div className="dim" style={{ fontSize: 13 }}>
            {changes
              ? "No topology changes recorded for the latest run — the map matched prior knowledge."
              : "Waiting for the latest run's observations…"}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {groups
              .filter(([, , items]) => items.length > 0)
              .map(([label, kind, items]) =>
                items.map((c, i) => (
                  <div
                    key={`${label}-${c.key}-${i}`}
                    className="row"
                    style={{ alignItems: "center", gap: 8, fontSize: 13 }}
                  >
                    <span className={`change-tag change-${kind}`}>{label}</span>
                    <span className="mono">{c.label || c.key}</span>
                  </div>
                ))
              )}
          </div>
        )}
      </div>
    </>
  );
}
