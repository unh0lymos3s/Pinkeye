"use client";
// Agent Chat: a chat-first workspace. Give the LLM planner a scope + objective (or just start
// typing) and watch it work — its reasoning, findings, tool calls and cross-run "network changes"
// all stream in over Server-Sent Events, reconnecting to an in-flight run after a reload. Run
// configuration (engagement, scope, scope guard, persona, tools, seed target, objective) lives
// entirely behind the gear button now (`ControlPanel`); the vertical `PipelineRail` on the left is
// the only other chrome. Everything else on this page is the transcript and the composer.
//
// Everything here is read-only visibility over the existing scope-guarded runtime: the objective is
// guidance, never authorization, and every tool call the agent makes is still checked against the
// engagement's signed scope before anything executes.
import { useEffect, useMemo, useRef, useState } from "react";
import ControlPanel from "./ControlPanel";
import PipelineRail from "./PipelineRail";
import SessionSwitcher from "./SessionSwitcher";
import Markdown from "./Markdown";
import { SeverityBadge } from "../ui";
import {
  abortRun,
  ApiAuthError,
  createRun,
  fetchTranscript,
  listProfiles,
  listTools,
  openRunEventStream,
  sendReply,
  updateScopeGuard,
  type Engagement,
  type Profile,
  type RunEvent,
  type Tool,
} from "../../lib/api";
import { useEngagement } from "../../lib/useEngagement";
import {
  createSession,
  deleteSession,
  getActiveSessionId,
  loadSessions,
  setActiveSessionId,
  titleFromObjective,
  updateSession,
  type Session,
} from "../../lib/sessions";

// Legacy single-run pointer, from before chat sessions existed. Read exactly once on mount, purely to
// migrate a still-in-flight run into a session of its own (see the mount effect) — nothing after that
// writes to or reads this key again; sessions.ts is the sole source of truth from there on.
const RUN_KEY = "eye.agentRunId";
// Persists the rail's collapse state across reloads (the control panel deliberately does not need
// the same treatment — it's a transient popover, not a layout choice).
const RAIL_KEY = "eye.agentRailOpen";
const DEFAULT_OBJECTIVE = "Discover the attack surface of the seed host and identify exploitable services.";
const DEFAULT_TARGET = "10.0.0.5";
const FALLBACK_STAGES = [
  "recon",
  "dynamic scan",
  "static scan",
  "threat intel",
  "exploitation",
  "credentials",
  "report",
];
// "aborted" is a run-runtime addition (Workstream A) for the operator-initiated abort button: the run
// emits its own status(aborted) event and the client must treat it exactly like completed/failed —
// every terminality check in this file goes through this one Set, so adding it here is the whole fix.
const TERMINAL = new Set(["completed", "failed", "rejected", "aborted"]);

// Tool -> pipeline stage, mirroring agent-runtime/runtime/pipeline.py (_TOOL_STAGE). Presentation
// only: it lets the pipeline rail dim stages the operator has switched off via the tool library.
// Unknown tools fall back to the first stage, matching stage_of().
const TOOL_STAGE: Record<string, string> = {
  nmap: "recon",
  nuclei: "dynamic scan",
  ffuf: "dynamic scan",
  nikto: "dynamic scan",
  zap: "dynamic scan",
  semgrep: "static scan",
  gitleaks: "static scan",
  trivy: "static scan",
  cve_lookup: "threat intel",
  virustotal: "threat intel",
  tls_cert: "threat intel",
  exploit: "exploitation",
  post_exploit: "exploitation",
  credential_attack: "credentials",
};
const stageOf = (tool: string) => TOOL_STAGE[tool] || FALLBACK_STAGES[0];
// "report" is a terminal presentation stage with no tool of its own, so it is always part of the pipeline.
const ALWAYS_STAGES = new Set(["report"]);

// Resolve the operator's chosen profile string (a persona id or one of its legacy aliases, e.g.
// "full" -> the overseer) against the loaded roster. Case-insensitive to match the backend's
// `personas.resolve()`. Returns undefined before the roster has loaded (or if the API is an older
// build that returned nothing usable) — every caller below treats "no persona resolved" as "show
// today's behaviour" rather than crashing.
function resolveProfile(profiles: Profile[], picked: string): Profile | undefined {
  const needle = picked.toLowerCase();
  return profiles.find(
    (p) => p.id.toLowerCase() === needle || p.name.toLowerCase() === needle || p.aliases.some((a) => a.toLowerCase() === needle)
  );
}

// The persona-scoped tool set: exactly what that persona may reach, nothing else. The orchestrator
// owns no tools of its own (it delegates), so it gets the full registry. Defensive fallbacks: no
// persona resolved yet, or a persona whose `tools` list is empty/missing, both fall back to "every
// registered tool" rather than stranding the operator with a blank, unusable selection.
function toolsForPersona(persona: Profile | undefined, allTools: Tool[]): Tool[] {
  if (!persona || persona.orchestrator) return allTools;
  if (!persona.tools || persona.tools.length === 0) return allTools;
  const owned = new Set(persona.tools);
  return allTools.filter((t) => owned.has(t.name));
}

// One-line scope summary for the topbar: prefers the network scope (CIDRs/domains — what most
// engagements actually set), falling back to allowed artifacts (e.g. a SAST upload path) when there
// is no network scope at all. Real values, not a count, same "operator's proof of authorization"
// principle the control panel's scope detail follows.
function scopeSummary(eng: Engagement | undefined): string {
  const scope = eng?.scope;
  if (!scope) return "no scope recorded";
  const net = [...(scope.allowed_cidrs || []), ...(scope.allowed_domains || [])];
  if (net.length) return net.join(", ");
  if (scope.allowed_artifacts && scope.allowed_artifacts.length) return scope.allowed_artifacts.join(", ");
  return "no scope recorded";
}

// Topbar persona suffix: stage when the persona owns one, else "orchestrator"/"generalist" — text
// only, per §4 of the redesign spec (no glyph, no accent color anywhere in this UI).
function personaSuffix(p: Profile | undefined): string {
  if (!p) return "";
  if (p.stage) return ` · ${p.stage}`;
  if (p.orchestrator) return " · orchestrator";
  if (p.generalist) return " · generalist";
  return "";
}

export default function AgentChat() {
  const { engagements, selected, select, refresh } = useEngagement();
  const [objective, setObjective] = useState(DEFAULT_OBJECTIVE);
  const [target, setTarget] = useState(DEFAULT_TARGET);
  const [runId, setRunId] = useState<string>("");
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [aborting, setAborting] = useState(false);

  // Chat sessions (chat-UI contract, sessions ask): a browser-local, named pointer to a run id — see
  // web/lib/sessions.ts for why this needs no backend support at all.
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSessionId, setActiveSessionIdState] = useState<string>("");

  // Tool library: the registered tools and the operator's per-run selection. `enabled === null`
  // means "not yet loaded"; once tools arrive we default to every tool checked.
  const [tools, setTools] = useState<Tool[]>([]);
  const [enabled, setEnabled] = useState<Set<string> | null>(null);

  // Agent profile: which personality drives the assessment. Holds a persona id or legacy alias
  // ("full" = the Overseer orchestrator delegating to specialist personas; a persona id/alias like
  // "scout"/"recon" runs that one focused persona; "flat"/"jack" = the generalist). Seeded to the
  // legacy "full" alias so a run can launch before /profiles has even responded — see the loader
  // effect below, which snaps this to the orchestrator's real id once the roster arrives.
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState("full");

  // The composer's single text box, shared between its two jobs: a reply draft while the agent is
  // waiting on an ask_user prompt, and an objective draft when there's no live run (see Composer).
  const [composerValue, setComposerValue] = useState("");
  const [sending, setSending] = useState(false);

  // Scope guard for the active engagement, lifted from web/app/page.tsx (which owns the identical
  // toggle for the landing page) rather than duplicated ad hoc — same updateScopeGuard() + refresh()
  // call, held here so this page can drive its own topbar/control-panel state independently.
  const [guardBusy, setGuardBusy] = useState(false);
  const [guardStatus, setGuardStatus] = useState("");

  // The gear-button panel. Unlike the rail, this does not persist across reloads — it's a transient
  // popover the operator opens to configure a run, not a layout preference.
  const [controlPanelOpen, setControlPanelOpen] = useState(false);

  // The pipeline rail's open/closed state, persisted so a collapsed rail stays collapsed on reload.
  const [railOpen, setRailOpen] = useState(true);
  useEffect(() => {
    if (typeof window === "undefined") return;
    const saved = localStorage.getItem(RAIL_KEY);
    if (saved !== null) setRailOpen(saved === "1");
  }, []);
  function toggleRail() {
    setRailOpen((o) => {
      const next = !o;
      if (typeof window !== "undefined") localStorage.setItem(RAIL_KEY, next ? "1" : "0");
      return next;
    });
  }

  const streamRef = useRef<AbortController | null>(null);
  const lastSeqRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  // Seqs that arrived over the live SSE stream (as opposed to the initial transcript replay on
  // reconnect). Only these get the streaming-reveal treatment — replaying old history should show
  // instantly, not re-animate the whole run.
  const liveSeqsRef = useRef<Set<number>>(new Set());
  // The run id this page is *currently* supposed to be displaying, kept in a ref (not just the
  // `runId` state) so an async callback scheduled before a session switch — most importantly the
  // reconnect-after-error timer in openStream's onError below — can tell it's stale and skip itself
  // instead of resurrecting the wrong run's tail into the newly active session. This is the fix for
  // exactly the cross-session bleed the sessions feature would otherwise introduce: without it, a
  // dropped connection's retry timer only checks "is some stream running right now?", which is still
  // true (or falsely false) after a switch regardless of *which* run it was tailing.
  const currentRunIdRef = useRef<string>("");
  useEffect(() => {
    currentRunIdRef.current = runId;
  }, [runId]);

  // Load the tool library once; default to all tools enabled.
  useEffect(() => {
    listTools()
      .then((t) => {
        setTools(t);
        setEnabled((prev) => prev ?? new Set(t.map((x) => x.name)));
      })
      .catch(() => {});
    listProfiles()
      .then((p) => {
        setProfiles(p.profiles);
        // Snap the pre-load "full" placeholder to the roster's actual orchestrator id, but only if
        // the operator hasn't already picked something else in the meantime — "full" still resolves
        // fine as a legacy alias either way, this just makes the topbar/panel show the real persona.
        setProfile((prev) => {
          if (prev !== "full") return prev;
          const orchestrator = p.profiles.find((x) => x.orchestrator);
          return orchestrator ? orchestrator.id : prev;
        });
      })
      .catch(() => {});
  }, []);

  // Point this page at a session: bind runId to it, wipe the transcript/stream state, and — if the
  // session already has a run — replay its transcript and reconnect the SSE tail (the same
  // replay-then-tail sequence the old single-run reconnect effect used, just parameterized on
  // whichever session is now active instead of always the one global RUN_KEY). Every caller below
  // (mount, switch, new, delete-fallback) funnels through this so there is exactly one place that
  // resets event/stream state, which is what keeps a session switch from bleeding the old run's
  // events into the new session's view.
  function loadIntoView(session: Session) {
    currentRunIdRef.current = session.runId;
    setRunId(session.runId);
    setEvents([]);
    lastSeqRef.current = 0;
    liveSeqsRef.current = new Set();
    setStatus("");
    if (session.engagementId) select(session.engagementId);
    setProfile(session.personaId || "full");
    setTarget(session.target || DEFAULT_TARGET);
    setObjective(session.objective || DEFAULT_OBJECTIVE);
    if (!session.runId) return;
    fetchTranscript(session.runId)
      .then((t) => {
        // The operator may have already switched to a different session while this fetch was in
        // flight — a stale response landing here must not clobber whatever's now on screen.
        if (currentRunIdRef.current !== session.runId) return;
        setEvents(t.events);
        lastSeqRef.current = t.events.length ? t.events[t.events.length - 1].seq : 0;
        const last = t.events[t.events.length - 1];
        if (!last || !(last.kind === "status" && TERMINAL.has(last.data?.status))) {
          openStream(session.runId, lastSeqRef.current);
        }
      })
      .catch(() => {});
  }

  // On mount: load whatever sessions this browser already knows about and reopen the one that was
  // active, exactly like the old single-run effect reconnected to RUN_KEY. First-ever visit (no
  // sessions, no legacy run) gets one empty session so the switcher is never empty-handed; a visit
  // from *before* sessions existed (a legacy RUN_KEY with no session wrapping it yet) gets that run
  // migrated into a session of its own so an in-flight run isn't orphaned by this feature shipping.
  useEffect(() => {
    let list = loadSessions();
    if (list.length === 0) {
      const legacyRunId = typeof window !== "undefined" ? localStorage.getItem(RUN_KEY) || "" : "";
      const migrated = createSession(legacyRunId ? { runId: legacyRunId, title: "Session 1" } : {});
      list = [migrated];
    }
    setSessions(list);
    const savedActive = getActiveSessionId();
    const active = list.find((s) => s.id === savedActive) || list[0];
    setActiveSessionIdState(active.id);
    setActiveSessionId(active.id);
    loadIntoView(active);
    return () => streamRef.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep the transcript pinned to the newest message. The chat is uncapped (the whole run shows as
  // one flowing interface), so we follow a sentinel at the end rather than scrolling an inner box.
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [events.length]);

  // While a "thinking" bubble is still streaming its text in, keep nudging the view along —
  // instant (not smooth) so it doesn't fight the scroll-on-new-message animation above.
  const stickToBottom = () => bottomRef.current?.scrollIntoView({ behavior: "auto", block: "end" });

  function openStream(id: string, after: number) {
    streamRef.current?.abort();
    const controller = openRunEventStream(id, after, {
      onEvent: (ev) => {
        // A newer stream (a relaunch, or a session switch) has already superseded this one — this
        // callback belongs to a controller nobody points at anymore, so it must not touch state.
        if (streamRef.current !== controller) return;
        lastSeqRef.current = Math.max(lastSeqRef.current, ev.seq);
        liveSeqsRef.current.add(ev.seq);
        setEvents((prev) => (prev.some((p) => p.seq === ev.seq) ? prev : [...prev, ev]));
        if (ev.kind === "status" && TERMINAL.has(ev.data?.status)) {
          controller.abort();
          if (streamRef.current === controller) streamRef.current = null;
        }
      },
      onDone: () => {
        if (streamRef.current === controller) streamRef.current = null;
      },
      onError: (err) => {
        if (streamRef.current !== controller) return; // superseded — nothing to surface or retry
        streamRef.current = null;
        if (err instanceof ApiAuthError) {
          // Retrying with the same missing/invalid key would just fail again — surface it and stop
          // (the operator fixes the key via the nav, which triggers a fresh launch/reconnect).
          setStatus(err.status === 401 ? "authentication required — enter an API key in the nav" : err.message);
          return;
        }
        // Connection dropped for some other reason. Resume tailing from the last seq, unless the run
        // already ended — the same bounded, throttled retry the old EventSource.onerror handler used.
        // Gated on `currentRunIdRef` rather than just "is nothing streaming right now": the operator
        // may have switched sessions (or started a new run) during the 1.5s wait, in which case `id`
        // is no longer the run this page is looking at and resuming it here would bleed the old
        // session's events into whatever's on screen now.
        setTimeout(() => {
          if (currentRunIdRef.current === id && !streamRef.current && !isTerminal(latestRef.current)) {
            openStream(id, lastSeqRef.current);
          }
        }, 1500);
      },
    });
    streamRef.current = controller;
  }

  // Keep a ref to the latest events for the reconnect timer (closures capture stale state otherwise).
  const latestRef = useRef<RunEvent[]>([]);
  latestRef.current = events;

  // Launches a run. `explicitObjective`, when given a non-empty string, wins over the control
  // panel's `objective` field — this is what lets the composer double as the launcher (chat-first):
  // typing straight into the chat box and hitting Enter launches with that text as the objective,
  // falling back to whatever's already sitting in the control panel when the box is empty.
  async function onLaunch(explicitObjective?: string) {
    if (!selected) {
      setStatus("select an engagement first (⚙)");
      return;
    }
    if (!target.trim()) {
      setStatus("set a seed target first (⚙)");
      return;
    }
    const obj = explicitObjective?.trim() || objective;
    setBusy(true);
    setStatus("launching agent run (scope-checked)…");
    setEvents([]);
    lastSeqRef.current = 0;
    try {
      const run = await createRun(selected, {
        target: target.trim(),
        mode: "agent",
        objective: obj,
        profile,
        // Omit when everything is selected so the backend treats it as "all tools".
        enabledTools: enabled && enabled.size < tools.length ? [...enabled] : undefined,
      });
      setRunId(run.id);
      currentRunIdRef.current = run.id;
      setStatus(`run ${run.id.slice(0, 8)} — ${run.status}`);
      // Keep the control panel's objective field in sync with what actually launched, so reopening
      // it later shows the real objective rather than a stale draft.
      if (explicitObjective?.trim()) setObjective(obj);
      // Bind the new run to the active session (chat sessions ask): a session's runId is "whichever
      // run this conversation most recently launched". An untitled session (still showing the "New
      // session" placeholder) titles itself from the objective the same way chat products name a
      // thread after its first message, rather than making the operator name it up front.
      if (activeSessionId) {
        const current = sessions.find((s) => s.id === activeSessionId);
        const patch: Partial<Session> = {
          runId: run.id,
          engagementId: selected,
          personaId: profile,
          target: target.trim(),
          objective: obj,
        };
        if (!current || current.title === "New session") patch.title = titleFromObjective(obj);
        setSessions(updateSession(activeSessionId, patch));
      }
      openStream(run.id, 0);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  // Send the operator's reply to a waiting ask_user prompt. The backend echoes it back as a
  // `user_reply` event over SSE, so we don't optimistically insert it — we just clear the draft.
  async function submitReply(text: string) {
    const t = text.trim();
    if (!t || !runId || sending) return;
    setSending(true);
    try {
      await sendReply(runId, t);
      setComposerValue("");
    } catch (e) {
      setStatus(`reply failed: ${String(e)}`);
    } finally {
      setSending(false);
    }
  }

  // Flip the scope-guard bypass for the selected engagement — identical to the toggle on the landing
  // page (web/app/page.tsx), just held here so this page's topbar/control panel can drive it without
  // reaching into that page's state.
  async function onToggleGuard() {
    if (!selected || guardBusy) return;
    setGuardBusy(true);
    setGuardStatus(guardEnabled ? "disabling scope guard…" : "re-enabling scope guard…");
    try {
      await updateScopeGuard(selected, !guardEnabled);
      await refresh();
      setGuardStatus("");
    } catch (e) {
      // A 403 here means the key is operator-not-admin — the shared auth-notice banner in the nav
      // already surfaces that; this local status line just confirms nothing changed.
      setGuardStatus(`error: ${String(e)}`);
    } finally {
      setGuardBusy(false);
    }
  }

  // Switch the page to a different session: tear down whatever's currently streaming *before*
  // touching any state (loadIntoView resets events/lastSeq/liveSeqs), so there is no window where a
  // leftover in-flight event from the old stream lands on top of the new session's blank slate.
  function switchToSession(id: string) {
    if (id === activeSessionId) return;
    const s = sessions.find((x) => x.id === id);
    if (!s) return;
    streamRef.current?.abort();
    streamRef.current = null;
    setActiveSessionIdState(id);
    setActiveSessionId(id);
    loadIntoView(s);
  }

  // A brand-new session starts with an empty transcript and the composer in launch mode (no runId),
  // carrying over the current engagement/persona/target as a convenience (those are "environment"
  // choices an operator rarely changes per-conversation) but resetting the objective back to the
  // baseline seed text, since that's the part that actually represents "what to talk about next".
  function onNewSession() {
    streamRef.current?.abort();
    streamRef.current = null;
    const fresh = createSession({ engagementId: selected, personaId: profile, target });
    setSessions((prev) => [...prev, fresh]);
    setActiveSessionIdState(fresh.id);
    currentRunIdRef.current = "";
    setRunId("");
    setEvents([]);
    lastSeqRef.current = 0;
    liveSeqsRef.current = new Set();
    setStatus("");
    setComposerValue("");
    setObjective(DEFAULT_OBJECTIVE);
  }

  function onRenameSession(id: string, title: string) {
    setSessions(updateSession(id, { title }));
  }

  // Deleting only forgets this browser's pointer — the run itself (if any) still exists server-side
  // and is unaffected; SessionSwitcher's confirm copy says as much. Deleting the *active* session
  // needs the same full teardown as switching away from it, then falls back to another session (or
  // spins up a fresh empty one if that was the last one) so the switcher is never left pointing at
  // nothing.
  function onDeleteSession(id: string) {
    const wasActive = id === activeSessionId;
    const updated = deleteSession(id);
    setSessions(updated);
    if (!wasActive) return;
    streamRef.current?.abort();
    streamRef.current = null;
    const next = updated[0] || createSession({});
    if (updated.length === 0) setSessions([next]);
    setActiveSessionIdState(next.id);
    setActiveSessionId(next.id);
    loadIntoView(next);
  }

  // Halt a live run (abort button ask). The backend does the actual work — it emits a `warning` then
  // a terminal `status: aborted` event over the SSE stream already open, which flows through the
  // normal onEvent path above and flips `live` false via TERMINAL exactly like completed/failed — so
  // there is deliberately no local "mark it aborted" state change here, only the request and a status
  // line for the two outcomes that don't produce their own event (network failure, or a 409 because
  // the run beat the operator to finishing).
  async function onAbort() {
    if (!runId || aborting) return;
    setAborting(true);
    try {
      const result = await abortRun(runId);
      if (!result.ok) setStatus("run already finished — nothing to abort");
    } catch (e) {
      setStatus(`abort failed: ${String(e)}`);
    } finally {
      setAborting(false);
    }
  }

  const view = useMemo(() => derive(events, profiles), [events, profiles]);

  const activeProfile = useMemo(() => resolveProfile(profiles, profile), [profiles, profile]);

  // Switching persona resets the tool selection to that persona's full toolkit — the whole point of
  // scoping the tool library is that it always reflects "everything this persona can currently
  // reach", not a stale selection left over from whoever was picked before. Fires once tools have
  // loaded and again whenever the persona changes (or the roster itself finishes loading, changing
  // what `activeProfile` resolves to for the same `profile` string).
  useEffect(() => {
    if (tools.length === 0) return;
    setEnabled(new Set(toolsForPersona(activeProfile, tools).map((t) => t.name)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile, tools.length, profiles.length]);

  // Stages the current tool selection keeps "on": a stage is live if at least one of its tools is
  // enabled (plus the always-on terminal stages). Used to dim deselected phases on the pipeline rail
  // so it visibly reflects the tool library — both before launch and during the run. A single-
  // specialist profile pins the rail to that specialist's stage so it reflects the chosen profile.
  const enabledStages = useMemo(() => {
    if (activeProfile?.stage) return new Set<string>([...ALWAYS_STAGES, activeProfile.stage]);
    if (!enabled) return new Set(view.stages); // library not loaded yet: assume all on
    const on = new Set<string>(ALWAYS_STAGES);
    for (const name of enabled) on.add(stageOf(name));
    return on;
  }, [enabled, view.stages, activeProfile]);

  // Scope guard status for the selected engagement, read straight off the list `useEngagement()`
  // already loaded (no extra fetch). Absent `scope` (older control-plane build, or an engagement
  // created before this shipped) means the guard is on — the documented server-side default — so
  // this only ever flags the explicit, opt-in "off" state, never a missing field.
  const activeEngagement = engagements.find((e) => e.id === selected);
  const guardEnabled = activeEngagement?.scope?.scope_guard_enabled !== false;

  // The active persona's topbar identity: label + stage, text only — no glyph, no accent color
  // anywhere in this UI (redesign spec §4). Falls back to the raw picked string before /profiles has
  // responded, same as everywhere else in this file.
  const activePersonaLabel = `${activeProfile?.label || profile}${personaSuffix(activeProfile)}`;

  // A run counts as "live" only while it exists and hasn't reached a terminal status — this is what
  // the composer uses to decide between replying and launching (see Composer below).
  const live = !!runId && !view.terminal;

  return (
    <div className="agent-workspace">
      <PipelineRail
        stages={view.stages}
        gated={view.gated}
        enabledStages={enabledStages}
        currentStage={view.currentStage}
        currentIndex={view.currentIndex}
        stageIndex={view.stageIndex}
        open={railOpen}
        onToggle={toggleRail}
        toolsUsed={view.toolsUsed}
        budgetMax={view.budgetMax}
      />

      <div className="agent-main">
        <div className={`agent-topbar${guardEnabled ? "" : " guard-off"}`}>
          <span className="topbar-item">
            <SessionSwitcher
              sessions={sessions}
              activeId={activeSessionId}
              onSelect={switchToSession}
              onCreate={onNewSession}
              onRename={onRenameSession}
              onDelete={onDeleteSession}
            />
          </span>
          <span className="topbar-item">
            <b>{activeEngagement?.name || "no engagement"}</b>
          </span>
          <span className="topbar-item">{scopeSummary(activeEngagement)}</span>
          <span className="topbar-item">{activePersonaLabel}</span>
          <span className="topbar-item">
            {guardEnabled ? "scope guard on" : "⚠ scope guard disabled — every target authorized"}
          </span>
          {view.status && (
            <span className="live">
              {!view.terminal && <span className="beat" />}
              {view.status}
            </span>
          )}
          {/* Abort button: next to the run status, since that's exactly where an operator reaching
              for "stop" looks first — visible the instant a run goes live, regardless of whether the
              composer happens to be in reply/idle/launch mode at the time. */}
          {live && (
            <button type="button" className="btn btn-abort" onClick={onAbort} disabled={aborting}>
              {aborting ? "Aborting…" : "Abort"}
            </button>
          )}
        </div>

        <div className="card chat chat-flat">
          {events.length === 0 && (
            <div className="dim" style={{ textAlign: "center", padding: "28px 0", fontSize: 13 }}>
              No run yet — type an objective below and press Enter to launch the agent, or open ⚙ to
              set the seed target, persona and tools first.
            </div>
          )}
          {events.map((ev) =>
            // Events a specialist sub-agent produced carry a `subagent` label; nest them under the
            // subagent_started header so a delegated pass reads as one indented group.
            ev.data?.subagent ? (
              <div key={ev.seq} className="nested-sub">
                <Bubble
                  ev={ev}
                  live={liveSeqsRef.current.has(ev.seq)}
                  onReveal={stickToBottom}
                  profiles={profiles}
                  runPersonaLabel={view.personaLabel}
                />
              </div>
            ) : (
              <Bubble
                key={ev.seq}
                ev={ev}
                live={liveSeqsRef.current.has(ev.seq)}
                onReveal={stickToBottom}
                profiles={profiles}
                runPersonaLabel={view.personaLabel}
              />
            )
          )}
          <div ref={bottomRef} />
        </div>

        <Composer
          pendingAsk={view.pendingAsk}
          live={live}
          value={composerValue}
          onChange={setComposerValue}
          sending={sending}
          busy={busy}
          canLaunch={!!selected && !!target.trim()}
          onSendReply={submitReply}
          onLaunch={(text) => {
            onLaunch(text);
            setComposerValue("");
          }}
          gearOpen={controlPanelOpen}
          onToggleGear={() => setControlPanelOpen((o) => !o)}
        />
      </div>

      <ControlPanel
        open={controlPanelOpen}
        onClose={() => setControlPanelOpen(false)}
        engagements={engagements}
        selected={selected}
        onSelectEngagement={select}
        activeEngagement={activeEngagement}
        guardEnabled={guardEnabled}
        guardBusy={guardBusy}
        guardStatus={guardStatus}
        onToggleGuard={onToggleGuard}
        profiles={profiles}
        profile={profile}
        onProfileChange={setProfile}
        tools={tools}
        enabled={enabled}
        onEnabledChange={setEnabled}
        target={target}
        onTargetChange={setTarget}
        objective={objective}
        onObjectiveChange={setObjective}
        onLaunch={() => onLaunch()}
        busy={busy}
        status={status}
      />
    </div>
  );
}

// The chat's reverse channel doubles as its launcher — the crux of "chat-first". Its mode is derived
// purely from run state, never a separate flag the operator has to manage:
//   - "reply": a run is live and the agent is waiting on an ask_user prompt — Enter sends the reply,
//     exactly as before.
//   - "launch": there is no live run (none yet, or the last one finished) — the box is enabled and
//     Enter launches a new run using the typed text as the objective, falling back to the control
//     panel's objective when the box is empty.
//   - "idle": a run is live but not currently asking anything — the agent is working, so the box is
//     informational only, same as today's disabled-with-a-hint state.
function Composer({
  pendingAsk,
  live,
  value,
  onChange,
  sending,
  busy,
  canLaunch,
  onSendReply,
  onLaunch,
  gearOpen,
  onToggleGear,
}: {
  pendingAsk: RunEvent | null;
  live: boolean;
  value: string;
  onChange: (v: string) => void;
  sending: boolean;
  busy: boolean;
  canLaunch: boolean;
  onSendReply: (text: string) => void;
  onLaunch: (text: string) => void;
  gearOpen: boolean;
  onToggleGear: () => void;
}) {
  const waiting = !!pendingAsk;
  const kind = pendingAsk?.data?.kind || "question";
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Focus the box as soon as the agent asks, so the operator can just start typing.
  useEffect(() => {
    if (waiting) inputRef.current?.focus();
  }, [waiting, pendingAsk?.seq]);

  const mode: "reply" | "launch" | "idle" = waiting ? "reply" : live ? "idle" : "launch";

  const placeholder =
    mode === "reply"
      ? kind === "permission"
        ? "Approve or deny — or type an instruction…"
        : "Type your reply to the agent…"
      : mode === "launch"
      ? canLaunch
        ? "Type a message / objective and press Enter to launch a run…"
        : "Select an engagement and a seed target (⚙) to launch a run…"
      : "The agent will prompt you here when it needs a decision.";

  // Only "idle" (a run is live but not asking anything) disables the box outright — launch mode is
  // never disabled, even with nothing configured yet, so the composer is never a dead end.
  const inputDisabled = mode === "idle" || (mode === "reply" && sending) || (mode === "launch" && busy);

  function submit() {
    if (mode === "reply") onSendReply(value);
    else if (mode === "launch") onLaunch(value);
  }

  const sendDisabled =
    mode === "idle" ? true : mode === "reply" ? sending || !value.trim() : busy || !canLaunch;

  return (
    <div className={`composer${waiting ? " active" : ""}`}>
      {waiting && (
        <div className="composer-head">
          <span className="beat" />
          the agent is waiting on your {kind === "permission" ? "approval" : "reply"}
        </div>
      )}
      <div className="composer-row">
        <button
          type="button"
          className="composer-gear"
          onClick={onToggleGear}
          aria-expanded={gearOpen}
          aria-label="Run configuration"
        >
          ⚙
        </button>
        <input
          ref={inputRef}
          className="input"
          style={{ flex: 1 }}
          value={value}
          disabled={inputDisabled}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
        />
        {mode === "reply" && kind === "permission" && (
          <>
            <button className="btn" onClick={() => onSendReply("Approved — proceed.")} disabled={sending}>
              ✓ Approve
            </button>
            <button
              className="btn"
              onClick={() => onSendReply("Denied — do not run that. Continue with non-intrusive steps.")}
              disabled={sending}
            >
              ✕ Deny
            </button>
          </>
        )}
        <button className="btn btn-primary" onClick={submit} disabled={sendDisabled}>
          {mode === "reply" ? (sending ? "Sending…" : "Send") : mode === "launch" ? (busy ? "Launching…" : "Launch") : "Send"}
        </button>
      </div>
    </div>
  );
}

// Resolve the persona byline for an agent-authored bubble (thinking/ask/tool lines): the sub-agent
// that produced it when the event carries `subagent` (a persona id — see the chat-UI contract §5),
// otherwise the run-level persona label from the `plan` event, falling back to today's generic
// "agent" when neither is present. Label only — never glyph/accent (redesign spec §4).
function personaLabelForEvent(
  d: Record<string, any>,
  profiles: Profile[],
  runPersonaLabel: string | undefined
): string {
  if (d.subagent) {
    const found = profiles.find((p) => p.id === d.subagent);
    return found?.label || d.persona_label || d.subagent;
  }
  return runPersonaLabel || "agent";
}

// Same idea for subagent_started/subagent_finished, which name the persona directly via `persona`/
// `persona_label` rather than via a `subagent` id on some other event. Falls back to the pre-persona
// `d.specialist` field so an older backend build still renders something sensible.
function subagentPersonaLabel(d: Record<string, any>, profiles: Profile[]): string {
  const found = d.persona ? profiles.find((p) => p.id === d.persona) : undefined;
  return d.persona_label || found?.label || d.persona || d.specialist || "specialist";
}

function isTerminal(events: RunEvent[]): boolean {
  const last = [...events].reverse().find((e) => e.kind === "status");
  return !!last && TERMINAL.has(last.data?.status);
}

// Derive all display state from the ordered event list plus the loaded persona roster — pure, so the
// UI is a function of the stream (and, for persona labels, of what /profiles has resolved so far).
function derive(events: RunEvent[], profiles: Profile[]) {
  const plan = events.find((e) => e.kind === "plan");
  const stages: string[] = plan?.data?.stages || FALLBACK_STAGES;
  const gated: string[] = plan?.data?.gated_stages || [];
  const budgetMax: number = plan?.data?.budget?.max_tool_calls || 40;
  // The run-level persona (chat-UI contract §5): the `plan` event's own `persona`/`persona_label`,
  // resolved against the roster by id in case an older backend build sends the id without the
  // human-readable label. This is the attribution every agent-authored bubble falls back to when it
  // isn't itself part of a delegated sub-agent pass.
  const planPersona = plan?.data?.persona ? profiles.find((p) => p.id === plan.data.persona) : undefined;
  const personaLabel: string | undefined = plan?.data?.persona_label || planPersona?.label;

  const finished = events.filter((e) => e.kind === "tool_finished");
  const toolsUsed = finished.length;
  const findingCount = events.filter((e) => e.kind === "finding").length;
  const changeCount = events.filter((e) => e.kind === "memory_delta").length;

  const statusEvents = events.filter((e) => e.kind === "status");
  const lastStatus = statusEvents[statusEvents.length - 1]?.data?.status || "";
  const terminal = TERMINAL.has(lastStatus);

  const stageEvents = events.filter((e) => e.data?.stage);
  let currentStage = stageEvents[stageEvents.length - 1]?.data?.stage || stages[0];
  if (terminal) currentStage = "report";
  const stageIndex = (s: string) => stages.indexOf(s);
  const currentIndex = stageIndex(currentStage);

  const lastStarted = Math.max(0, ...events.filter((e) => e.kind === "tool_started").map((e) => e.seq));
  const lastFinished = Math.max(0, ...finished.map((e) => e.seq));
  const running = !terminal && lastStarted > lastFinished;
  const runningEv = running
    ? [...events].reverse().find((e) => e.kind === "tool_started")
    : undefined;
  const last = events[events.length - 1];
  const thinking = !terminal && !running && last?.kind === "thinking";

  let activity = "";
  if (running && runningEv) activity = `▶ running ${runningEv.data.tool} on ${runningEv.data.target}…`;
  else if (thinking) activity = "◍ thinking…";

  // Interactive: an ask_user prompt is "pending" while it has no reply after it and the run is live.
  const askEvents = events.filter((e) => e.kind === "ask");
  const replyEvents = events.filter((e) => e.kind === "user_reply");
  const lastAsk = askEvents[askEvents.length - 1];
  const lastReplySeq = replyEvents.length ? replyEvents[replyEvents.length - 1].seq : 0;
  const pendingAsk = lastAsk && lastAsk.seq > lastReplySeq && !terminal ? lastAsk : null;

  const statusLabel = terminal
    ? `run ${lastStatus}`
    : pendingAsk
    ? "awaiting your input"
    : lastStatus
    ? "running"
    : "";
  if (pendingAsk && !activity) activity = "◍ waiting for your reply…";

  return {
    stages,
    gated,
    budgetMax,
    toolsUsed,
    findingCount,
    changeCount,
    terminal,
    currentStage,
    currentIndex,
    stageIndex,
    activity,
    status: statusLabel,
    pendingAsk,
    personaLabel,
  };
}

// Simulated token-stream reveal for a "thinking" bubble: the backend's LLM call is blocking and
// hands back the full text in one event (agent-runtime has no token-level streaming today), so we
// fake the live-generation feel client-side by revealing it word-by-word. Only bubbles that arrived
// over the live SSE stream animate — a reconnect's transcript replay renders instantly, since
// re-typing an entire past run on every reload would be slow and wouldn't read as "live" anyway.
function StreamingThinkingText({
  text,
  animate,
  onReveal,
}: {
  text: string;
  animate: boolean;
  onReveal?: () => void;
}) {
  // Keep whitespace as its own tokens so re-joining the revealed slice reproduces the text exactly.
  const words = useMemo(() => text.split(/(\s+)/), [text]);
  const [count, setCount] = useState(animate ? 0 : words.length);

  useEffect(() => {
    if (!animate) return;
    // Scale how many words land per tick so a very long thought still finishes in a couple of
    // seconds instead of visibly crawling, while a short one still reads as a real typewriter.
    const chunk = Math.max(1, Math.ceil(words.length / 150));
    const id = setInterval(() => {
      setCount((c) => {
        const next = Math.min(words.length, c + chunk);
        if (next >= words.length) clearInterval(id);
        return next;
      });
      onReveal?.();
    }, 28);
    return () => clearInterval(id);
    // Runs once per mount: this bubble's seq (and therefore its React key) never changes, so the
    // text/animate props are effectively fixed for its lifetime.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Streaming-vs-markdown tradeoff: a "thinking" bubble is genuinely markdown, but only once it's
  // whole. Feeding an in-progress reveal straight through react-markdown would parse a truncated
  // document on every tick — an unclosed ``` fence or a lone `**` reads as literal characters one
  // tick and flips to a code block/bold run the next, so the bubble would visibly flicker/reformat
  // as it typed rather than reading as a steady reveal. So: render plain text (with the blinking
  // caret) while still streaming, exactly as before, and swap to the fully rendered markdown the
  // instant the reveal completes — which for a replayed (non-live) bubble is immediately, since
  // `count` starts at `words.length` and this branch is taken on the very first render.
  const streaming = animate && count < words.length;
  if (streaming) {
    return (
      <div className="body">
        {words.slice(0, count).join("")}
        <span className="stream-caret" />
      </div>
    );
  }
  return <Markdown text={text} />;
}

function Bubble({
  ev,
  live,
  onReveal,
  profiles,
  runPersonaLabel,
}: {
  ev: RunEvent;
  live: boolean;
  onReveal?: () => void;
  // Loaded persona roster, used to resolve a sub-agent's label by id (see personaLabelForEvent /
  // subagentPersonaLabel above) — never rendered as glyph or accent color (redesign spec §4).
  profiles: Profile[];
  // The top-level run's persona label (derive()'s `view.personaLabel`) — the fallback attribution
  // for any bubble that isn't itself part of a delegated sub-agent pass.
  runPersonaLabel?: string;
}) {
  const d = ev.data || {};
  switch (ev.kind) {
    case "plan": {
      const stages: string[] = d.stages || [];
      const gated: string[] = d.gated_stages || [];
      const budget = d.budget?.max_tool_calls;
      return (
        <div className="msg sys plan-msg">
          <span className="who">
            ▚ plan
            {d.persona_label && <span className="mono"> · {d.persona_label}</span>}
          </span>
          <div className="body">
            pipeline:{" "}
            {stages.map((s, i) => (
              <span key={s}>
                {i > 0 && <span className="dim"> › </span>}
                <span className={gated.includes(s) ? "dim" : undefined}>{s}</span>
              </span>
            ))}
            {budget != null && <span className="dim"> · budget {budget} tool calls</span>}
            {gated.length > 0 && (
              <span className="dim"> · gated by scope: {gated.join(", ")}</span>
            )}
          </div>
        </div>
      );
    }
    case "thinking": {
      const label = personaLabelForEvent(d, profiles, runPersonaLabel);
      return (
        <div className="msg reason">
          <span className="who">◍ {label}</span>
          <StreamingThinkingText text={d.text} animate={live} onReveal={onReveal} />
        </div>
      );
    }
    case "tool_call": {
      const label = personaLabelForEvent(d, profiles, runPersonaLabel);
      return (
        <div className="msg sys">
          <span className="who">{label}</span>
          <span className="tag">{d.stage}</span>
          → calling <b>{d.tool}</b> on <span className="mono">{d.target}</span>
          {d.intensity && <span className="dim"> · {d.intensity}</span>}
        </div>
      );
    }
    case "tool_finished": {
      const label = personaLabelForEvent(d, profiles, runPersonaLabel);
      if (d.denied)
        return (
          <div className="msg tool denied">
            <span className="who">
              ⛔ {label} · {d.tool} — denied by scope guard
            </span>
            <div className="body">
              <Markdown text={d.summary || ""} />
            </div>
          </div>
        );
      return (
        <div className="msg tool">
          <span className="who">
            ✓ {label} · {d.tool}
          </span>
          <div className="body">
            {d.error ? <span className="err">error: {d.error}</span> : <Markdown text={d.summary || ""} />}
          </div>
        </div>
      );
    }
    case "finding":
      return (
        <div className="msg finding">
          <SeverityBadge severity={d.severity} />
          <span className="title">{d.title}</span>
          <span className="mono dim">{d.target}</span>
          {d.cve && <span className="tag">{d.cve}</span>}
        </div>
      );
    case "memory_delta":
      return (
        <div className="msg change">
          <span className="who">
            {d.change === "newly_exploitable" ? "⚠ exploitable" : `Δ ${d.change}`}
          </span>
          <div className="body">{d.label || d.key}</div>
        </div>
      );
    case "ask": {
      const kind = d.kind || "question";
      const glyph = kind === "permission" ? "🔒" : kind === "recommendation" ? "💡" : "❔";
      const label = personaLabelForEvent(d, profiles, runPersonaLabel);
      return (
        <div className={`msg ask ask-${kind}`}>
          <span className="who">
            {glyph} {label} needs you · {kind}
          </span>
          <div className="body">{d.question}</div>
          {d.action && (
            <div className="ask-action">
              proposed action: <span className="mono">{d.action}</span>
            </div>
          )}
        </div>
      );
    }
    case "user_reply":
      return (
        <div className={`msg user-reply${d.auto ? " auto" : ""}`}>
          <span className="who">{d.auto ? "⏱ no reply" : "🧑 you"}</span>
          <div className="body">{d.text}</div>
        </div>
      );
    case "subagent_started": {
      const label = subagentPersonaLabel(d, profiles);
      return (
        <div className="msg sys subagent-start">
          <span className="who persona-label">▼ {label}</span>
          <div className="body">
            {d.stage && <span className="tag">{d.stage}</span>} on <span className="mono">{d.target}</span>
            {d.focus && <span className="dim"> · focus: {d.focus}</span>}
          </div>
        </div>
      );
    }
    case "subagent_finished": {
      const label = subagentPersonaLabel(d, profiles);
      if (d.error)
        return (
          <div className="msg tool denied">
            <span className="who">✕ {label}</span>
            <div className="body">{d.error}</div>
          </div>
        );
      return (
        <div className="msg sys subagent-end">
          <span className="who persona-label">▲ {label} done</span>
          <div className="body">
            <Markdown text={d.summary || ""} />
            <span className="dim">
              · {d.findings ?? 0} findings · {d.tool_calls ?? 0} calls
            </span>
          </div>
        </div>
      );
    }
    case "refusal": {
      const label =
        d.stage === "reinforce"
          ? "model declined — re-asserting authorization"
          : d.stage === "fallback"
          ? "model declined — routing to fallback model"
          : "model declined the authorized step";
      return (
        <div className="msg sys refusal">
          <span className="who">↺ {label}</span>
          {d.text && <div className="body dim">{d.text}</div>}
        </div>
      );
    }
    case "error":
      return (
        <div className="msg tool denied">
          <span className="who">✕ {d.scope === "llm" ? "model error" : "run error"}</span>
          <div className="body">{d.message || d.error}</div>
        </div>
      );
    case "warning":
      // Currently just the scope-guard-disabled notice (`{"scope":"scope_guard", "message": …}`),
      // but rendered generically off `d.message` so any future warning kind shows up the same way
      // without a code change here.
      return (
        <div className="msg sys warning">
          <span className="who">⚠ warning</span>
          <div className="body">{d.message || "the agent raised a warning"}</div>
        </div>
      );
    case "status":
      if (TERMINAL.has(d.status))
        return <div className="msg sys done-line">— run {d.status} —</div>;
      return null;
    default:
      return null;
  }
}
