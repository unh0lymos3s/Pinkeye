"use client";
// Knowledge graph: the persisted network map, with an engagement filter that lives on this page
// (workstream C, round 5) instead of just trailing the globally-selected engagement. Plus the
// cross-run "what changed" diff for the most recently launched run. Split out from the landing
// page so "/" stays a bare launcher and this page owns the graph full-time.
import { useEffect, useRef, useState } from "react";
import GraphView, { PINK, WHITE } from "../GraphView";
import { SectionTitle } from "../ui";
import { fetchChanges, fetchGraph, fetchMap, type Graph, type GraphNode, type MemoryChanges } from "../../lib/api";
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

// Every label graph.py writes (Engagement, IP, Port, Service, Endpoint, Finding, AttackChain) is
// MERGEd with `engagement_id` stamped onto it -- that's how the per-engagement `/graph` query
// scopes its MATCH. So the cross-engagement `/map` response can be filtered down to a chosen set
// of engagements purely client-side, without inventing anything the backend doesn't already send.
// A node missing the property (nothing in the current schema omits it, but the type only marks it
// optional) can't be attributed to any engagement, so it's dropped rather than kept in every filter.
function filterByEngagements(g: Graph, ids: Set<string>): Graph {
  const keep = new Set(
    g.nodes.filter((n: GraphNode) => ids.has(String(n.props.engagement_id ?? ""))).map((n) => n.id)
  );
  return {
    nodes: g.nodes.filter((n) => keep.has(n.id)),
    // Drop edges whose endpoints didn't survive the node cut instead of handing GraphView a
    // dangling reference -- it tolerates that (an edge just fails to find both ends and isn't
    // drawn), but leaving it in would make the header's edge count lie about what's on screen.
    edges: g.edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
  };
}

export default function MapPage() {
  const { engagements, selected, select } = useEngagement();
  const { lastRunId } = useLastRun(selected);
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] });
  const [changes, setChanges] = useState<MemoryChanges | null>(null);
  const [fullscreen, setFullscreen] = useState(false);

  // The map's own filter: either "all engagements" (the old full-map checkbox, folded in as an
  // option here instead of a disconnected toggle) or an explicit subset picked below. Empty + not
  // "all" means nothing is chosen yet.
  const [pickAll, setPickAll] = useState(false);
  const [pick, setPick] = useState<Set<string>>(new Set());

  // Seed the filter from the globally-selected engagement exactly once, so the map opens on
  // whatever the operator was already looking at on the dashboard/query page rather than blank.
  // After this the filter is free to diverge -- see the sync effect below for how it stays
  // coherent with the rest of the app when that matters.
  const seeded = useRef(false);
  useEffect(() => {
    if (!seeded.current && selected) {
      setPick(new Set([selected]));
      seeded.current = true;
    }
  }, [selected]);

  function togglePick(id: string) {
    if (pickAll) {
      // Coming off "all", narrow straight to just the clicked engagement rather than resurrecting
      // whatever subset happened to be picked before "all" was chosen.
      setPickAll(false);
      setPick(new Set([id]));
      return;
    }
    setPick((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // Local-only filter, with one exception: once it narrows to exactly one engagement, push that
  // engagement into the shared selection. That's the case the rest of the app (and the changes
  // panel below) assumes, so keeping it in sync means the map and everything else agree without
  // the operator having to set the engagement twice. "All" or a multi-engagement subset has no
  // single id to hand back, so global selection is left untouched in those cases and the changes
  // panel labels itself explicitly instead (see ChangesPanel).
  useEffect(() => {
    if (!pickAll && pick.size === 1) {
      const only = pick.values().next().value as string;
      if (only && only !== selected) select(only);
    }
  }, [pickAll, pick]); // eslint-disable-line react-hooks/exhaustive-deps

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

  // Poll the graph so new findings appear as scans land. Source depends on the filter: a single
  // engagement hits the already-scoped /graph endpoint; "all" or a multi-engagement subset both
  // pull the full cross-engagement map, the latter filtering it client-side (see filterByEngagements).
  useEffect(() => {
    const tick = () => {
      let p: Promise<Graph>;
      if (pickAll) {
        p = fetchMap();
      } else if (pick.size === 0) {
        p = Promise.resolve({ nodes: [], edges: [] });
      } else if (pick.size === 1) {
        p = fetchGraph(pick.values().next().value as string);
      } else {
        p = fetchMap().then((g) => filterByEngagements(g, pick));
      }
      p.then(setGraph).catch(() => {});
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => clearInterval(t);
  }, [pickAll, pick]);

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
  const selectedEngagement = engagements.find((e) => e.id === selected);

  // Human label for "what am I looking at" -- shown in the header so the filter state is never a
  // mystery, per the round-5 ask.
  const filterLabel = pickAll
    ? "All engagements"
    : pick.size === 0
    ? "no engagement selected"
    : pick.size === 1
    ? engagements.find((e) => e.id === pick.values().next().value)?.name || "1 engagement"
    : `${pick.size} engagements`;

  // The changes panel tracks the globally-selected engagement's last run regardless of the map
  // filter; it's only "the same thing" the map is showing when the filter has narrowed to exactly
  // that one engagement. Anything else (all, or a multi-engagement subset) needs an explicit label
  // so the two panels never look like they're describing the same scope when they aren't.
  const changesMismatch = pickAll || pick.size !== 1 || !pick.has(selected);

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Knowledge Graph</h1>
          <p className="dim mono" style={{ margin: "4px 0 0", fontSize: 12 }}>
            Showing: {filterLabel}
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {engagements.length === 0 ? (
            <span className="dim" style={{ fontSize: 13 }}>
              no engagements yet
            </span>
          ) : (
            <>
              <button
                type="button"
                className="mini-btn"
                style={
                  pickAll
                    ? { marginLeft: 0, background: WHITE, color: PINK, fontWeight: 650, borderColor: "transparent" }
                    : { marginLeft: 0 }
                }
                onClick={() => setPickAll(true)}
              >
                All engagements
              </button>
              {engagements.map((e) => {
                const active = !pickAll && pick.has(e.id);
                return (
                  <button
                    key={e.id}
                    type="button"
                    className="mini-btn"
                    style={
                      active
                        ? { marginLeft: 0, background: WHITE, color: PINK, fontWeight: 650, borderColor: "transparent" }
                        : { marginLeft: 0 }
                    }
                    onClick={() => togglePick(e.id)}
                    title={`Toggle ${e.name} in the map filter`}
                  >
                    {e.name}
                  </button>
                );
              })}
            </>
          )}
        </div>
      </div>

      <SectionTitle
        action={
          <span className="live">
            {nodeCount > 0 && <span className="beat" />}
            {filterLabel} · {nodeCount} nodes · {edgeCount} edges
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
        {nodeCount === 0 && <EmptyState engagementsCount={engagements.length} pickAll={pickAll} pick={pick} selectedName={selectedEngagement?.name} />}
        {nodeCount > 0 && (
          <div className="dim" style={{ textAlign: "center", padding: "8px 0 2px", fontSize: 11.5 }}>
            drag to pan · scroll or +/− to zoom · double-click to reset · click a node to collapse/expand
          </div>
        )}
      </div>

      {lastRunId && (
        <ChangesPanel changes={changes} engagementName={selectedEngagement?.name} mismatch={changesMismatch} />
      )}
    </main>
  );
}

// Three distinct reasons the map can come up empty, each worth saying plainly rather than folding
// into one generic "no data" line: no engagements exist at all, nothing is picked yet, or a pick
// (single or multi) simply has no graph behind it.
function EmptyState({
  engagementsCount,
  pickAll,
  pick,
  selectedName,
}: {
  engagementsCount: number;
  pickAll: boolean;
  pick: Set<string>;
  selectedName?: string;
}) {
  let message: string;
  if (engagementsCount === 0) {
    message = "No engagements yet — launch one from the home page to start building the graph.";
  } else if (!pickAll && pick.size === 0) {
    message = 'Select an engagement above (or "All engagements") to see its graph.';
  } else if (!pickAll && pick.size === 1) {
    message = `No graph data yet for ${selectedName || "this engagement"} — launch a run from the home page to populate hosts, ports, services, and findings.`;
  } else if (!pickAll && pick.size > 1) {
    message = `No nodes in the map belong to the ${pick.size} selected engagements.`;
  } else {
    message = "No graph data yet — launch a run from the home page to populate hosts, ports, services, and findings.";
  }
  return (
    <div className="dim" style={{ textAlign: "center", padding: "12px 0 4px", fontSize: 13 }}>
      {message}
    </div>
  );
}

// The cross-run memory diff for the most recent run: new/changed/gone topology and newly-exploitable
// targets, so an operator sees at a glance what this run added over prior knowledge. Fed by the
// /changes endpoint; the same deltas the agent chat surfaces inline. `mismatch` flags when the map
// above is showing something other than this exact engagement (see the note in MapPage), so the
// scope difference is stated rather than left to guesswork.
function ChangesPanel({
  changes,
  engagementName,
  mismatch,
}: {
  changes: MemoryChanges | null;
  engagementName?: string;
  mismatch: boolean;
}) {
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
        Changes since last run{engagementName ? ` — ${engagementName}` : ""}
      </SectionTitle>
      <div className="card card-pad">
        {mismatch && (
          <div className="dim mono" style={{ fontSize: 11.5, marginBottom: 8 }}>
            Tracking {engagementName || "the last-selected engagement"}'s last run regardless of the map filter above.
          </div>
        )}
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
