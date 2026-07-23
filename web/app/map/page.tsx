"use client";
// Knowledge graph: the persisted network map for the active engagement (or every engagement, via
// "full map"), plus the cross-run "what changed" diff for the most recently launched run. Split out
// from the landing page so "/" stays a bare launcher and this page owns the graph full-time.
import { useEffect, useState } from "react";
import GraphView, { PINK, WHITE } from "../GraphView";
import { SectionTitle } from "../ui";
import { fetchChanges, fetchGraph, fetchMap, type Graph, type MemoryChanges } from "../../lib/api";
import { useEngagement } from "../../lib/useEngagement";
import { useLastRun } from "../../lib/useLastRun";

const NODE_LEGEND: [string, boolean][] = [
  ["Engagement", false],
  ["IP / Host", false],
  ["Port", false],
  ["Service", true],
  ["Finding", true],
];

const STATUS_LEGEND: [string, string][] = [
  ["⚠ exploitable", "rgba(255,255,255,0.95)"],
  ["new", "rgba(255,255,255,0.95)"],
  ["changed", "rgba(255,255,255,0.55)"],
  ["gone", "rgba(255,255,255,0.3)"],
];

export default function MapPage() {
  const { selected } = useEngagement();
  const { lastRunId } = useLastRun(selected);
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] });
  const [full, setFull] = useState(false);
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

  const nodeCount = graph.nodes.length;
  const edgeCount = graph.edges.length;

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Knowledge Graph</h1>
          <p className="page-sub">
            Hosts, ports, services, and findings, persisted across runs for the active engagement.
          </p>
        </div>
        <label className="live" style={{ cursor: "pointer" }}>
          <input type="checkbox" checked={full} onChange={(e) => setFull(e.target.checked)} />
          full map (all engagements)
        </label>
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
        Graph
      </SectionTitle>
      <div className={`card graph-card${fullscreen ? " graph-fullscreen" : ""}`} style={{ padding: 12 }}>
        {fullscreen && (
          <button className="mini-btn graph-fs-exit" onClick={() => setFullscreen(false)}>
            ✕ Exit fullscreen (Esc)
          </button>
        )}
        <div className="legend" style={{ padding: "4px 6px 12px" }}>
          {NODE_LEGEND.map(([label, pop]) => (
            <span className="item" key={label}>
              <span
                className="swatch"
                style={
                  pop
                    ? { background: WHITE, border: `1.5px solid ${PINK}` }
                    : { background: PINK, border: `1.5px solid ${WHITE}` }
                }
              />
              {label}
            </span>
          ))}
          {STATUS_LEGEND.map(([label, color]) => (
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
            No graph data yet — launch a run from the home page to populate hosts, ports, services, and findings.
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
