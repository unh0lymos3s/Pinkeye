"use client";
// Client-side chat sessions, layered on top of server-persisted run transcripts (chat-UI contract,
// "chat sessions" ask). The control plane has no session concept at all — a run is its unit of
// persistence — so a "session" here is nothing more than a named, browser-local pointer to a run id
// plus the launch parameters that produced it. History survives a session switch because the
// transcript itself lives server-side (fetchTranscript/openRunEventStream in ./api already replay
// and reconnect); this module only tracks *which* run a given named conversation currently points at.
// Deleting a session therefore can never delete backend data — it just forgets the pointer, and the
// UI that calls deleteSession() below should say so explicitly rather than imply data loss.

const SESSIONS_KEY = "eye.agentSessions.v1";
const ACTIVE_KEY = "eye.agentActiveSession.v1";

export type Session = {
  id: string;
  title: string;
  runId: string; // "" until a run has actually been launched inside this session
  engagementId: string;
  personaId: string;
  target: string;
  objective: string;
  createdAt: string;
  lastActiveAt: string;
};

function isSession(x: any): x is Session {
  return (
    x &&
    typeof x === "object" &&
    typeof x.id === "string" &&
    typeof x.title === "string" &&
    typeof x.runId === "string" &&
    typeof x.engagementId === "string" &&
    typeof x.personaId === "string" &&
    typeof x.target === "string" &&
    typeof x.objective === "string" &&
    typeof x.createdAt === "string" &&
    typeof x.lastActiveAt === "string"
  );
}

// Tolerant load: a missing key, a foreign-shaped blob (an older version of this key, or something
// else entirely written under it), or outright unparseable JSON must never throw — each degrades to
// "no sessions recorded" so a corrupted localStorage entry costs the operator a fresh start, not a
// broken page.
export function loadSessions(): Session[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(SESSIONS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    const list = Array.isArray(parsed?.sessions) ? parsed.sessions : Array.isArray(parsed) ? parsed : [];
    return list.filter(isSession);
  } catch {
    return [];
  }
}

function save(sessions: Session[]): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(SESSIONS_KEY, JSON.stringify({ v: 1, sessions }));
  } catch {
    /* storage full/disabled — the caller's in-memory state is still correct for this tab's lifetime */
  }
}

export function getActiveSessionId(): string {
  if (typeof window === "undefined") return "";
  try {
    return localStorage.getItem(ACTIVE_KEY) || "";
  } catch {
    return "";
  }
}

export function setActiveSessionId(id: string): void {
  if (typeof window === "undefined") return;
  try {
    if (id) localStorage.setItem(ACTIVE_KEY, id);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch {
    /* ignore — same reasoning as save() above */
  }
}

function newId(): string {
  // crypto.randomUUID is available in every browser this app targets; the fallback only exists so an
  // exotic/old runtime degrades to a merely-unlikely-to-collide id instead of throwing.
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return `s_${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

// Creates a session and makes it the active one (every call site that creates a session immediately
// switches to it — there's no scenario in this UI where you'd create one without opening it).
export function createSession(seed: Partial<Session> = {}): Session {
  const now = new Date().toISOString();
  const session: Session = {
    id: newId(),
    title: seed.title || "New session",
    runId: seed.runId || "",
    engagementId: seed.engagementId || "",
    personaId: seed.personaId || "",
    target: seed.target || "",
    objective: seed.objective || "",
    createdAt: now,
    lastActiveAt: now,
  };
  const sessions = loadSessions();
  sessions.push(session);
  save(sessions);
  setActiveSessionId(session.id);
  return session;
}

// Returns the full updated list so callers can setSessions(...) straight off the result rather than
// re-reading storage.
export function updateSession(id: string, patch: Partial<Session>): Session[] {
  const sessions = loadSessions().map((s) =>
    s.id === id ? { ...s, ...patch, id: s.id, lastActiveAt: new Date().toISOString() } : s
  );
  save(sessions);
  return sessions;
}

export function deleteSession(id: string): Session[] {
  const sessions = loadSessions().filter((s) => s.id !== id);
  save(sessions);
  if (getActiveSessionId() === id) setActiveSessionId("");
  return sessions;
}

// Titles an untitled session from its first launched objective — the same "name the conversation
// after its first message" idiom chat products use, so the operator never has to name a session
// up front just to start one.
export function titleFromObjective(objective: string): string {
  const trimmed = objective.trim().replace(/\s+/g, " ");
  if (!trimmed) return "New session";
  return trimmed.length > 48 ? `${trimmed.slice(0, 45)}…` : trimmed;
}
