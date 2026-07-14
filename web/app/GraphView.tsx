"use client";
// Self-contained SVG knowledge-graph view. Runs a tiny force simulation client-side so we don't
// pull in an external graph library. Colors nodes by their Neo4j label. Renders responsively via
// a fixed simulation coordinate space projected through an SVG viewBox.
import { useEffect, useMemo, useRef, useState } from "react";
import type { Graph } from "../lib/api";

const COLORS: Record<string, string> = {
  Engagement: "#8b5cf6",
  IP: "#3b82f6",
  Port: "#22c55e",
  Service: "#eab308",
  Finding: "#ef4444",
  Node: "#94a3b8",
};

const W = 960;
const H = 560;

type P = {
  id: string;
  label: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  title: string;
  exploitable: boolean; // Service/Endpoint proven exploitable, or a target device
  status: string; // cross-run memory status: new | changed | active | gone
};

// Ring color for a node's cross-run memory status; null = no status ring.
const STATUS_COLOR: Record<string, string> = {
  new: "#22c55e",
  changed: "#f59e0b",
  gone: "#64748b",
};

function nodeTitle(props: Record<string, unknown>): string {
  return (
    (props.address as string) ||
    (props.name as string) ||
    (props.title as string) ||
    (props.number != null ? `:${props.number}` : "") ||
    "node"
  );
}

export default function GraphView({ graph }: { graph: Graph }) {
  const [nodes, setNodes] = useState<P[]>([]);
  const [hover, setHover] = useState<string | null>(null);
  const raf = useRef<number>();

  // Seed node positions whenever the graph identity set changes.
  const seed = useMemo(() => graph.nodes.map((n) => n.id).join(","), [graph]);
  useEffect(() => {
    setNodes(
      graph.nodes.map((n, i) => ({
        id: n.id,
        label: n.label,
        title: nodeTitle(n.props),
        exploitable: Boolean(n.props.exploitable || n.props.is_target),
        status: (n.props.status as string) || "",
        x: W / 2 + Math.cos((i / Math.max(1, graph.nodes.length)) * 2 * Math.PI) * 180,
        y: H / 2 + Math.sin((i / Math.max(1, graph.nodes.length)) * 2 * Math.PI) * 180,
        vx: 0,
        vy: 0,
      }))
    );
  }, [seed]); // eslint-disable-line react-hooks/exhaustive-deps

  // Force simulation: repulsion between all nodes, spring pull along edges, gentle centering.
  useEffect(() => {
    if (nodes.length === 0) return;
    const step = () => {
      setNodes((prev) => {
        const next = prev.map((n) => ({ ...n }));
        const idx = new Map(next.map((n, i) => [n.id, i]));
        for (let i = 0; i < next.length; i++) {
          for (let j = i + 1; j < next.length; j++) {
            const a = next[i], b = next[j];
            let dx = a.x - b.x, dy = a.y - b.y;
            let d2 = dx * dx + dy * dy || 0.01;
            const f = 4000 / d2;
            const d = Math.sqrt(d2);
            a.vx += (dx / d) * f; a.vy += (dy / d) * f;
            b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
          }
        }
        for (const e of graph.edges) {
          const a = next[idx.get(e.source) ?? -1], b = next[idx.get(e.target) ?? -1];
          if (!a || !b) continue;
          const dx = b.x - a.x, dy = b.y - a.y;
          const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
          const f = (d - 90) * 0.02;
          a.vx += (dx / d) * f; a.vy += (dy / d) * f;
          b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
        }
        for (const n of next) {
          n.vx += (W / 2 - n.x) * 0.002;
          n.vy += (H / 2 - n.y) * 0.002;
          n.vx *= 0.85; n.vy *= 0.85;
          n.x += n.vx; n.y += n.vy;
        }
        return next;
      });
      raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  }, [seed, graph.edges]); // eslint-disable-line react-hooks/exhaustive-deps

  const pos = new Map(nodes.map((n) => [n.id, n]));

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      width="100%"
      style={{
        display: "block",
        background: "radial-gradient(circle at 50% 40%, #141a26, #0e121b)",
        borderRadius: 8,
        aspectRatio: `${W} / ${H}`,
      }}
    >
      {graph.edges.map((e, i) => {
        const a = pos.get(e.source), b = pos.get(e.target);
        if (!a || !b) return null;
        const active = hover && (e.source === hover || e.target === hover);
        return (
          <line
            key={i}
            x1={a.x} y1={a.y} x2={b.x} y2={b.y}
            stroke={active ? "#64748b" : "#2a3546"}
            strokeWidth={active ? 1.6 : 1}
          />
        );
      })}
      {nodes.map((n) => {
        const color = COLORS[n.label] || COLORS.Node;
        const active = hover === n.id;
        const r = n.label === "Finding" ? 9 : 7;
        const statusColor = STATUS_COLOR[n.status];
        const gone = n.status === "gone";
        const tip = [n.label, n.title].join(": ")
          + (n.exploitable ? "  ⚠ exploitable" : "")
          + (n.status ? `  (${n.status})` : "");
        return (
          <g
            key={n.id}
            onMouseEnter={() => setHover(n.id)}
            onMouseLeave={() => setHover((h) => (h === n.id ? null : h))}
            style={{ cursor: "default", opacity: gone ? 0.5 : 1 }}
          >
            {active && <circle cx={n.x} cy={n.y} r={r + 5} fill={color} opacity={0.18} />}
            {/* Exploitable ring: an amber halo flags a proven-exploitable service/endpoint or target device. */}
            {n.exploitable && (
              <circle cx={n.x} cy={n.y} r={r + 4} fill="none" stroke="#f59e0b" strokeWidth={2} opacity={0.95} />
            )}
            {/* Cross-run status ring: new / changed / gone from the memory engine. */}
            {statusColor && (
              <circle
                cx={n.x}
                cy={n.y}
                r={r + (n.exploitable ? 7 : 3)}
                fill="none"
                stroke={statusColor}
                strokeWidth={1.4}
                strokeDasharray={gone ? "3 2" : undefined}
                opacity={0.9}
              />
            )}
            <circle cx={n.x} cy={n.y} r={r} fill={color} stroke="#0e121b" strokeWidth={1.5} />
            {n.exploitable && (
              <text x={n.x} y={n.y + 3.5} fontSize={9} textAnchor="middle" fill="#0e121b" fontWeight={700}>
                !
              </text>
            )}
            <text x={n.x + r + 6} y={n.y + 4} fontSize={11} fill={active ? "#e8eaf0" : "#9aa5b8"}>
              {n.title}
            </text>
            <title>{tip}</title>
          </g>
        );
      })}
    </svg>
  );
}
