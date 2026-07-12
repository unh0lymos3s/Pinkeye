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
};

export function createRun(engagementId: string, opts: RunOptions) {
  const { target, tool = "nmap", intensity = "light", mode = "scan" } = opts;
  const body = mode === "agent" ? { target, mode } : { target, tool, intensity, mode };
  return fetch(`${BASE}/engagements/${engagementId}/runs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then(json<{ id: string; status: string }>);
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
