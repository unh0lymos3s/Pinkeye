"use client";
// Self-contained SVG knowledge-graph view. Runs a tiny force simulation client-side so we don't
// pull in an external graph library. Colors nodes by their Neo4j label. Renders responsively via
// a fixed simulation coordinate space projected through an SVG viewBox.
import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import type { Graph } from "../lib/api";

// Single source of truth for the two-color palette (SVG fill/stroke attributes can't read CSS
// vars). Kept in sync with --bg/--brand and --text in globals.css.
export const PINK = "#ff2da0";
export const WHITE = "#ffffff";

// Node fill/stroke by Neo4j label. "Pop" types (Service, Finding) render solid white so they read
// as the notable/active layer; "calm" structural types (Engagement, IP, Port) render hollow — pink
// fill matching the canvas, thin white outline — so they recede into the field.
const COLORS: Record<string, { fill: string; stroke: string }> = {
  Engagement: { fill: PINK, stroke: WHITE },
  IP: { fill: PINK, stroke: WHITE },
  Port: { fill: PINK, stroke: WHITE },
  Service: { fill: WHITE, stroke: PINK },
  Finding: { fill: WHITE, stroke: PINK },
  Node: { fill: PINK, stroke: WHITE },
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

// Ring color for a node's cross-run memory status; null = no status ring. All white, ramped by
// opacity so "new" (max attention) reads brightest and "gone" (least) fades toward the canvas.
const STATUS_COLOR: Record<string, string> = {
  new: "rgba(255, 255, 255, 0.95)",
  changed: "rgba(255, 255, 255, 0.55)",
  gone: "rgba(255, 255, 255, 0.3)",
};

// Label a node by the field that actually identifies its type, so the IP -> Port -> Service chain
// reads as e.g. "10.0.0.5" -> ":22/tcp" -> "ssh" instead of the IP repeated at every level. Every
// node carries `address` (the parent IP) for MERGE keying, so a type-blind lookup showed the IP
// everywhere — here the node's Neo4j label decides which property is its name.
function nodeTitle(label: string, props: Record<string, unknown>): string {
  const s = (v: unknown) => (v == null ? "" : String(v));
  switch (label) {
    case "Engagement":
      return s(props.name) || "engagement";
    case "IP":
      return s(props.address) || s(props.hostname) || "ip";
    case "Port": {
      const num = props.number ?? props.port;
      const proto = s(props.proto);
      return num != null ? `:${num}${proto ? `/${proto}` : ""}` : "port";
    }
    case "Service":
      return (
        s(props.name) ||
        s(props.product) ||
        (props.port != null ? `:${props.port}` : "") ||
        "service"
      );
    case "Endpoint":
      return s(props.url) || s(props.address) || "endpoint";
    case "Finding":
      return s(props.title) || s(props.category) || "finding";
    case "AttackChain":
      return s(props.title) || "chain";
    default:
      return s(props.address) || s(props.name) || s(props.title) || "node";
  }
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

export default function GraphView({ graph, fill = false }: { graph: Graph; fill?: boolean }) {
  const [nodes, setNodes] = useState<P[]>([]);
  const [hover, setHover] = useState<string | null>(null);
  const raf = useRef<number>();

  // Pan/zoom navigation: the viewBox is the "camera". Dragging pans it; the wheel zooms toward the
  // cursor; double-click resets. Node positions come from the simulation and are unaffected.
  const [view, setView] = useState({ x: 0, y: 0, w: W, h: H });
  const [panning, setPanning] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{ sx: number; sy: number; vx: number; vy: number } | null>(null);
  const resetView = () => setView({ x: 0, y: 0, w: W, h: H });

  const onDown = (e: ReactMouseEvent) => {
    drag.current = { sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y };
    setPanning(true);
  };
  const onMove = (e: ReactMouseEvent) => {
    const d = drag.current;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!d || !rect) return;
    setView((v) => ({
      ...v,
      x: d.vx - (e.clientX - d.sx) * (v.w / rect.width),
      y: d.vy - (e.clientY - d.sy) * (v.h / rect.height),
    }));
  };
  const endPan = () => {
    drag.current = null;
    setPanning(false);
  };

  // Wheel zoom needs a non-passive native listener so preventDefault stops the page from scrolling.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const factor = e.deltaY < 0 ? 0.85 : 1.0 / 0.85; // in / out
      setView((v) => {
        const nw = clamp(v.w * factor, W * 0.2, W * 3);
        const nh = nw * (H / W); // keep the coordinate-space aspect so nodes don't distort
        const fx = (e.clientX - rect.left) / rect.width;
        const fy = (e.clientY - rect.top) / rect.height;
        return { x: v.x + fx * v.w - fx * nw, y: v.y + fy * v.h - fy * nh, w: nw, h: nh };
      });
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  // Seed node positions whenever the graph identity set changes.
  const seed = useMemo(() => graph.nodes.map((n) => n.id).join(","), [graph]);
  useEffect(() => {
    setNodes(
      graph.nodes.map((n, i) => ({
        id: n.id,
        label: n.label,
        title: nodeTitle(n.label, n.props),
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
      ref={svgRef}
      viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`}
      width="100%"
      // In fullscreen the container drives the size (svg fills it, viewBox keeps it centered);
      // otherwise the fixed aspect ratio keeps the inline card a sensible height.
      height={fill ? "100%" : undefined}
      preserveAspectRatio="xMidYMid meet"
      onMouseDown={onDown}
      onMouseMove={onMove}
      onMouseUp={endPan}
      onMouseLeave={endPan}
      onDoubleClick={resetView}
      style={{
        display: "block",
        background: PINK,
        borderRadius: 8,
        cursor: panning ? "grabbing" : "grab",
        touchAction: "none",
        ...(fill ? { flex: 1, minHeight: 0, height: "100%" } : { aspectRatio: `${W} / ${H}` }),
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
            stroke={active ? "rgba(255, 255, 255, 0.8)" : "rgba(255, 255, 255, 0.35)"}
            strokeWidth={active ? 1.6 : 1}
          />
        );
      })}
      {nodes.map((n) => {
        const nc = COLORS[n.label] || COLORS.Node;
        const active = hover === n.id;
        const r = n.label === "Finding" ? 9 : 7;
        const statusColor = STATUS_COLOR[n.status];
        const gone = n.status === "gone";
        const dashed = gone || n.status === "changed";
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
            {active && <circle cx={n.x} cy={n.y} r={r + 5} fill={nc.fill} opacity={0.25} />}
            {/* Exploitable ring: a pulsing white halo flags a proven-exploitable service/endpoint or target device. */}
            {n.exploitable && (
              <circle cx={n.x} cy={n.y} r={r + 4} fill="none" stroke={WHITE} strokeWidth={2.2} opacity={0.95} />
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
                strokeDasharray={dashed ? "3 2" : undefined}
                opacity={0.9}
              />
            )}
            <circle cx={n.x} cy={n.y} r={r} fill={nc.fill} stroke={nc.stroke} strokeWidth={1.5} />
            {n.exploitable && (
              <text x={n.x} y={n.y + 3.5} fontSize={9} textAnchor="middle" fill={nc.stroke} fontWeight={700}>
                !
              </text>
            )}
            <text
              x={n.x + r + 6}
              y={n.y + 4}
              fontSize={11}
              fill={active ? WHITE : "rgba(255, 255, 255, 0.75)"}
              style={{ fontFamily: "var(--mono)" }}
            >
              {n.title}
            </text>
            <title>{tip}</title>
          </g>
        );
      })}
    </svg>
  );
}
