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

// ---- API key (operator-supplied credential) ----
//
// The control plane now requires at least a `viewer` X-API-Key on every route except /health (open
// dev mode — no EYE_API_KEYS configured — exempts this entirely and needs no key at all). The key is
// deliberately NOT a NEXT_PUBLIC_* env var: those are inlined into the client bundle at build time,
// which would ship the key to every browser that loads the page and bake it into the built image.
// Instead it is entered by the operator (see Nav.tsx) and kept in sessionStorage rather than
// localStorage, so it disappears when the tab/browser session ends instead of lingering indefinitely
// on a shared workstation.
const API_KEY_STORAGE_KEY = "eye.apiKey";

// Fired whenever the stored key changes (set or cleared), so any UI showing "key present?" can react.
export const API_KEY_EVENT = "eye:api-key-changed";
// Fired whenever a request comes back 401/403, so a single place (the nav) can surface it without
// every call site needing its own banner.
export const AUTH_NOTICE_EVENT = "eye:auth-notice";

export function getApiKey(): string {
  if (typeof window === "undefined") return "";
  try {
    return sessionStorage.getItem(API_KEY_STORAGE_KEY) || "";
  } catch {
    return ""; // storage disabled/unavailable (e.g. private mode) — behave as if no key is set
  }
}

export function setApiKey(key: string): void {
  if (typeof window === "undefined") return;
  try {
    const trimmed = key.trim();
    if (trimmed) sessionStorage.setItem(API_KEY_STORAGE_KEY, trimmed);
    else sessionStorage.removeItem(API_KEY_STORAGE_KEY);
  } catch {
    /* nothing we can do if storage is unavailable */
  }
  window.dispatchEvent(new Event(API_KEY_EVENT));
}

export function clearApiKey(): void {
  setApiKey("");
}

export type AuthNotice = { status: 401 | 403; message: string };

function notifyAuthNotice(detail: AuthNotice): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent<AuthNotice>(AUTH_NOTICE_EVENT, { detail }));
  }
}

// Thrown by `request()` on 401/403 so callers can distinguish "not authenticated" from any other
// failure. The message is a fixed, generic string — it never echoes the key or any server detail
// that could itself be sensitive.
export class ApiAuthError extends Error {
  status: 401 | 403;
  constructor(notice: AuthNotice) {
    super(notice.message);
    this.name = "ApiAuthError";
    this.status = notice.status;
  }
}

// Single funnel every API call goes through: attaches X-API-Key when a key is stored (and omits it
// otherwise, which is exactly what a server in open dev mode expects — no header needed), and turns
// 401/403 into a specific, actionable error instead of a generic failure or a blank screen.
async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const key = getApiKey();
  const headers = new Headers(init.headers);
  if (key) headers.set("X-API-Key", key);
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401 || res.status === 403) {
    const notice: AuthNotice =
      res.status === 401
        ? { status: 401, message: "API key missing or invalid — enter a key to continue." }
        : {
            status: 403,
            message: "This API key doesn't have permission for that action (needs a higher role).",
          };
    notifyAuthNotice(notice);
    throw new ApiAuthError(notice);
  }
  return res;
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.url} -> ${res.status}`);
  return res.json();
}

export function createEngagement(body: { name: string; allowed_cidrs: string[]; allowed_domains: string[] }) {
  return request(`/engagements`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then(json<Engagement>);
}

export function listEngagements() {
  return request(`/engagements`, { cache: "no-store" }).then(json<Engagement[]>);
}

export type RunOptions = {
  target: string;
  tool?: string;
  intensity?: string;
  mode?: "scan" | "agent";
  objective?: string;
  // Agent-mode tool library: the subset of tools the planner may use. Omit/empty = all tools.
  enabledTools?: string[];
  // Agent-mode profile: "full" (orchestrator) | a specialist name | "flat". Omit = "full".
  profile?: string;
};

export function createRun(engagementId: string, opts: RunOptions) {
  const { target, tool = "nmap", intensity = "light", mode = "scan", objective, enabledTools, profile } = opts;
  const body =
    mode === "agent"
      ? {
          target,
          mode,
          objective: objective || null,
          // Only send a selection when the operator narrowed it; empty/undefined means "all".
          enabled_tools: enabledTools && enabledTools.length ? enabledTools : null,
          profile: profile || null,
        }
      : { target, tool, intensity, mode };
  return request(`/engagements/${engagementId}/runs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then(json<{ id: string; status: string }>);
}

// ---- SAST source upload ----

export type SastUpload = {
  path: string; // extracted directory the scan targets (also added to the engagement's signed scope)
  kind: string; // "zip" | "tar" | "file"
  file_count: number;
  total_bytes: number;
  artifact: string;
};

// Upload a codebase (zip / tar / tar.gz) or a single source file for static analysis. The raw file
// is sent as the request body with the name in the query string — no multipart needed. The server
// extracts it, authorizes the extracted path in the engagement's signed scope, and returns the path
// a SAST run then targets.
export function uploadSast(engagementId: string, file: File) {
  const name = encodeURIComponent(file.name || "upload.zip");
  return request(`/engagements/${engagementId}/sast/upload?filename=${name}`, {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body: file,
  }).then(async (r) => {
    if (!r.ok) {
      let detail = `${r.status}`;
      try {
        detail = (await r.json())?.detail ?? detail;
      } catch {
        /* non-JSON error body */
      }
      throw new Error(detail);
    }
    return r.json() as Promise<SastUpload>;
  });
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
  return request(`/tools`, { cache: "no-store" }).then(json<Tool[]>);
}

// ---- agent profiles (who drives the assessment) ----

export type Profile = {
  name: string; // "full" | specialist kind | "flat"
  stage: string | null; // pipeline stage a specialist owns, or null
  description: string;
  gated_flag: string | null; // specialists that also need a signed-scope flag
};

export function listProfiles() {
  return request(`/profiles`, { cache: "no-store" }).then(json<{ profiles: Profile[] }>);
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
  | "error"
  | "ask" // the agent is asking the operator (permission / recommendation / question)
  | "user_reply" // the operator's reply, echoed into the transcript
  | "subagent_started" // the orchestrator delegated to a specialist sub-agent
  | "subagent_finished"; // a specialist sub-agent returned its summary

export type RunEvent = {
  engagement_id: string;
  run_id: string;
  seq: number;
  kind: RunEventKind;
  data: Record<string, any>;
  at: string;
};

export function fetchTranscript(runId: string) {
  return request(`/runs/${runId}/transcript`, { cache: "no-store" }).then(json<{ events: RunEvent[] }>);
}

// Send the operator's reply to a run waiting on an `ask_user` prompt (the interactive chat's
// reverse channel). Guidance/permission only — it can never widen the run's authorized scope.
export function sendReply(runId: string, text: string) {
  return request(`/runs/${runId}/reply`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text }),
  }).then(json<{ ok: boolean }>);
}

// ---- live run events: fetch-based SSE tail ----
//
// `GET /runs/{id}/events` now requires a viewer key, and the browser's EventSource API has no way to
// attach a request header — so it is structurally incapable of authenticating against this endpoint.
// We replace it with a fetch() + ReadableStream reader that attaches X-API-Key like every other call,
// decoding the `text/event-stream` wire format ("id: <seq>\ndata: <json>\n\n") by hand.
export type RunEventStreamHandlers = {
  onEvent: (ev: RunEvent) => void;
  onDone?: () => void;
  onError?: (err: unknown) => void;
};

// Opens the tail as an aborted-on-demand background reader. Returns the AbortController the caller
// must hold (in a ref, as the previous EventSource lived in one) and `.abort()` on unmount/run-change
// — the same teardown guarantee the old `esRef.current?.close()` gave, just via a different API.
export function openRunEventStream(
  runId: string,
  after: number,
  handlers: RunEventStreamHandlers
): AbortController {
  const controller = new AbortController();

  (async () => {
    let buf = "";
    try {
      const res = await request(`/runs/${runId}/events?after=${after}`, {
        signal: controller.signal,
        headers: { Accept: "text/event-stream" },
        cache: "no-store",
      });
      if (!res.ok || !res.body) throw new Error(`${res.url} -> ${res.status}`);

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        // Frames are separated by a blank line ("\n\n"). A frame can arrive split across two reads
        // (or several frames can arrive in one read), so only parse complete frames off the front of
        // the buffer and leave any trailing partial frame in place for the next chunk to complete —
        // parsing eagerly on a bare "\n" would silently drop or corrupt events mid-run.
        let idx: number;
        while ((idx = buf.indexOf("\n\n")) !== -1) {
          const frame = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (!frame.trim()) continue; // keep-alive / comment-only frame
          const dataLine = frame.split("\n").find((line) => line.startsWith("data:"));
          if (!dataLine) continue;
          const raw = dataLine.slice(5).trimStart();
          try {
            handlers.onEvent(JSON.parse(raw) as RunEvent);
          } catch {
            /* malformed frame — skip it rather than tearing down the whole stream */
          }
        }
      }
      handlers.onDone?.();
    } catch (err) {
      if (controller.signal.aborted) return; // deliberate teardown, not a stream failure
      handlers.onError?.(err);
    }
  })();

  return controller;
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
  return request(`/engagements/${engagementId}/memory`, { cache: "no-store" }).then(json<MemorySnapshot>);
}

export function fetchChanges(engagementId: string, runId: string) {
  return request(`/engagements/${engagementId}/changes?run_id=${runId}`, { cache: "no-store" }).then(
    json<MemoryChanges>
  );
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
  return request(`/engagements/${engagementId}/chains`, { cache: "no-store" }).then(json<Chain[]>);
}

export function validateFindings(engagementId: string) {
  return request(`/engagements/${engagementId}/validate`, { method: "POST" }).then(
    json<{ promoted: number }>
  );
}

// The report is plain text (see control-plane's PlainTextResponse) and used to be a direct <a href>
// link opened in a new tab. That no longer works once a key is required — a bare anchor navigation
// can't carry a header, and putting the key in the URL as a query param is exactly the credential
// leak (server logs, browser history, Referer) we're avoiding elsewhere. `openReport` instead fetches
// with the key attached and opens the result as a blob: URL, so the browser tab still gets the same
// "opened in a new tab" experience with no key ever touching the address bar.
export function reportUrl(engagementId: string) {
  return `${BASE}/engagements/${engagementId}/report`;
}

export async function openReport(engagementId: string): Promise<void> {
  const res = await request(`/engagements/${engagementId}/report`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.url} -> ${res.status}`);
  const text = await res.text();
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener,noreferrer");
  // Give the new tab time to load the blob before releasing it.
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

export function fetchReport(engagementId: string) {
  return request(`/engagements/${engagementId}/report`, { cache: "no-store" }).then((r) => {
    if (!r.ok) throw new Error(`${r.url} -> ${r.status}`);
    return r.text();
  });
}

export function fetchGraph(engagementId: string) {
  return request(`/engagements/${engagementId}/graph`, { cache: "no-store" }).then(json<Graph>);
}

export function fetchMap() {
  return request(`/map`, { cache: "no-store" }).then(json<Graph>);
}

export function fetchMetrics(engagementId: string) {
  return request(`/engagements/${engagementId}/metrics`, { cache: "no-store" }).then(json<Metrics>);
}

export function queryFindings(engagementId: string, params: Record<string, string>) {
  const qs = new URLSearchParams(params).toString();
  return request(`/engagements/${engagementId}/findings?${qs}`, { cache: "no-store" }).then(
    json<Finding[]>
  );
}

export function runCypher(engagementId: string, cypher: string) {
  return request(`/engagements/${engagementId}/graph/query`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ cypher }),
  }).then(json<{ rows: Record<string, unknown>[] }>);
}
