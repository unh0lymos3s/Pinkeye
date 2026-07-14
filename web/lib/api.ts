// Thin client for the control-plane API. Base URL is injected at build/run time.
export const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:9000";
const BASE = API_BASE;

export type GraphNode = { id: string; label: string; props: Record<string, unknown> };
export type GraphEdge = { source: string; target: string; type: string };
export type Graph = { nodes: GraphNode[]; edges: GraphEdge[] };

export type Engagement = { id: string; name: string };

export type Metrics = {
  hosts: number;
  exposed_endpoints: number;
  cves_identified: number;
  open_issues: number;
  findings_by_severity: Record<string, number>;
  runs: number;
};

export type Finding = {
  dedup_key: string;
  title: string;
  category: string;
  severity: string;
  state: string;
  confidence: number;
  target: string;
  cve: string | null;
  cwe: string | null;
  source_tool: string;
  times_seen: number;
  last_seen: string;
};

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.url} -> ${res.status}`);
  return res.json();
}

export function createEngagement(body: { name: string; allowed_cidrs: string[]; allowed_domains: string[] }) {
  return fetch(`${BASE}/engagements`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then(json<Engagement>);
}

export function listEngagements() {
  return fetch(`${BASE}/engagements`, { cache: "no-store" }).then(json<Engagement[]>);
}

export type RunOptions = {
  target: string;
  tool?: string;
  intensity?: string;
  mode?: "scan" | "agent";
  objective?: string;
  // Agent-mode tool library: the subset of tools the planner may use. Omit/empty = all tools.
  enabledTools?: string[];
};

export function createRun(engagementId: string, opts: RunOptions) {
  const { target, tool = "nmap", intensity = "light", mode = "scan", objective, enabledTools } = opts;
  const body =
    mode === "agent"
      ? {
          target,
          mode,
          objective: objective || null,
          // Only send a selection when the operator narrowed it; empty/undefined means "all".
          enabled_tools: enabledTools && enabledTools.length ? enabledTools : null,
        }
      : { target, tool, intensity, mode };
  return fetch(`${BASE}/engagements/${engagementId}/runs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then(json<{ id: string; status: string }>);
}

// ---- tool library (agent-mode tool selection) ----

export type Tool = {
  name: string;
  description: string;
  surface: string; // network | artifact | knowledge
  requires_flag: string | null; // offensive tools also need a signed-scope flag
  mcp: boolean;
};

export function listTools() {
  return fetch(`${BASE}/tools`, { cache: "no-store" }).then(json<Tool[]>);
}

// ---- live run events (chat interface) ----

export type RunEventKind =
  | "plan"
  | "thinking"
  | "tool_call"
  | "tool_started"
  | "tool_finished"
  | "finding"
  | "status"
  | "memory_delta"
  | "refusal"
  | "error";

export type RunEvent = {
  engagement_id: string;
  run_id: string;
  seq: number;
  kind: RunEventKind;
  data: Record<string, any>;
  at: string;
};

export function fetchTranscript(runId: string) {
  return fetch(`${BASE}/runs/${runId}/transcript`, { cache: "no-store" }).then(
    json<{ events: RunEvent[] }>
  );
}

// URL for an EventSource(SSE) live tail; `after` resumes from the last seq seen (reconnect/replay).
export function runEventsUrl(runId: string, after = 0) {
  return `${BASE}/runs/${runId}/events?after=${after}`;
}

// ---- cross-run network memory ----

export type MemoryService = {
  port: number;
  proto: string;
  service: string;
  product: string;
  exploitable: boolean;
};

export type MemoryDevice = {
  address: string;
  hostname: string | null;
  os: string | null;
  device_type: string | null;
  status: string;
  is_target: boolean;
  services: MemoryService[];
  exploitable_count: number;
};

export type MemorySnapshot = { devices: MemoryDevice[]; endpoints: string[] };

export type MemoryChangeEntry = { kind: string; key: string; label: string; before: any; after: any };
export type MemoryChanges = {
  added: MemoryChangeEntry[];
  changed: MemoryChangeEntry[];
  removed: MemoryChangeEntry[];
  newly_exploitable: MemoryChangeEntry[];
};

export function fetchMemory(engagementId: string) {
  return fetch(`${BASE}/engagements/${engagementId}/memory`, { cache: "no-store" }).then(
    json<MemorySnapshot>
  );
}

export function fetchChanges(engagementId: string, runId: string) {
  return fetch(`${BASE}/engagements/${engagementId}/changes?run_id=${runId}`, {
    cache: "no-store",
  }).then(json<MemoryChanges>);
}

export type Chain = {
  id?: string;
  title?: string;
  name?: string;
  severity?: string;
  steps?: unknown[];
  [k: string]: unknown;
};

export function fetchChains(engagementId: string) {
  return fetch(`${BASE}/engagements/${engagementId}/chains`, { cache: "no-store" }).then(json<Chain[]>);
}

export function validateFindings(engagementId: string) {
  return fetch(`${BASE}/engagements/${engagementId}/validate`, { method: "POST" }).then(
    json<{ promoted: number }>
  );
}

export function reportUrl(engagementId: string) {
  return `${BASE}/engagements/${engagementId}/report`;
}

export function fetchReport(engagementId: string) {
  return fetch(reportUrl(engagementId), { cache: "no-store" }).then((r) => {
    if (!r.ok) throw new Error(`${r.url} -> ${r.status}`);
    return r.text();
  });
}

export function fetchGraph(engagementId: string) {
  return fetch(`${BASE}/engagements/${engagementId}/graph`, { cache: "no-store" }).then(json<Graph>);
}

export function fetchMap() {
  return fetch(`${BASE}/map`, { cache: "no-store" }).then(json<Graph>);
}

export function fetchMetrics(engagementId: string) {
  return fetch(`${BASE}/engagements/${engagementId}/metrics`, { cache: "no-store" }).then(json<Metrics>);
}

export function queryFindings(engagementId: string, params: Record<string, string>) {
  const qs = new URLSearchParams(params).toString();
  return fetch(`${BASE}/engagements/${engagementId}/findings?${qs}`, { cache: "no-store" }).then(
    json<Finding[]>
  );
}

export function runCypher(engagementId: string, cypher: string) {
  return fetch(`${BASE}/engagements/${engagementId}/graph/query`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ cypher }),
  }).then(json<{ rows: Record<string, unknown>[] }>);
}
