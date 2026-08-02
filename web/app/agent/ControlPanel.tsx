"use client";
// The gear-button control panel: the *only* place run configuration lives now that /agent is a
// chat-first workspace (see docs/superpowers/specs/2026-07-23-shocking-pink-cyberpunk-redesign-design.md).
// Everything that used to be a stacked "Objective & scope" card above the chat now collapses into
// this one anchored panel: which engagement, what it actually authorizes, whether the scope guard
// is on, who's driving (persona), what tools they may reach, and the seed target/objective that
// launches a run. `page.tsx` owns all the state; this file is a pure render of what it's handed
// plus the two small dropdowns (persona list, tool library) that used to live inline in that card.
import { useEffect, useRef, useState } from "react";
import EngagementPicker from "../EngagementPicker";
import type { Engagement, Profile, Tool } from "../../lib/api";

export type ControlPanelProps = {
  open: boolean;
  onClose: () => void;
  // engagement + scope
  engagements: Engagement[];
  selected: string;
  onSelectEngagement: (id: string) => void;
  activeEngagement: Engagement | undefined;
  // scope guard
  guardEnabled: boolean;
  guardBusy: boolean;
  guardStatus: string;
  onToggleGuard: () => void;
  // personality
  profiles: Profile[];
  profile: string;
  onProfileChange: (id: string) => void;
  // tools
  tools: Tool[];
  enabled: Set<string> | null;
  onEnabledChange: (next: Set<string>) => void;
  // run inputs
  target: string;
  onTargetChange: (v: string) => void;
  objective: string;
  onObjectiveChange: (v: string) => void;
  onLaunch: () => void;
  busy: boolean;
  status: string;
};

// Tool -> pipeline stage, mirroring agent-runtime/runtime/pipeline.py (_TOOL_STAGE). This is a
// second copy of the same table `page.tsx` keeps — the file-ownership split means neither side can
// import the other's internals, and this one is only needed for the tool library's legacy "no
// persona roster loaded" grouping fallback below, so a small duplicated constant is cheaper than
// coupling the two files together for it.
const FALLBACK_STAGES = [
  "recon",
  "dynamic scan",
  "static scan",
  "threat intel",
  "exploitation",
  "credentials",
  "report",
];
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

// Resolve the operator's chosen profile string (a persona id or one of its legacy aliases) against
// the loaded roster. Case-insensitive to match the backend's `personas.resolve()`. The locked
// ControlPanelProps contract hands this panel the raw `profile` string rather than an already-
// resolved Profile, so every section that needs the resolved persona (scope, tools) does this
// lookup itself.
function resolveProfile(profiles: Profile[], picked: string): Profile | undefined {
  const needle = picked.toLowerCase();
  return profiles.find(
    (p) => p.id.toLowerCase() === needle || p.name.toLowerCase() === needle || p.aliases.some((a) => a.toLowerCase() === needle)
  );
}

// The persona-scoped tool set: exactly what that persona may reach, nothing else. The orchestrator
// owns no tools of its own (it delegates), so it gets the full registry — its dropdown groups tools
// by the specialist that owns them instead. No persona resolved yet, or a persona whose `tools`
// list is empty/missing, both fall back to "every registered tool" rather than a blank menu.
function toolsForPersona(persona: Profile | undefined, allTools: Tool[]): Tool[] {
  if (!persona || persona.orchestrator) return allTools;
  if (!persona.tools || persona.tools.length === 0) return allTools;
  const owned = new Set(persona.tools);
  return allTools.filter((t) => owned.has(t.name));
}

// Render a scope field that may or may not exist on this engagement — older API responses (or ones
// widened after this shipped) can be missing any of these, and a list can legitimately be empty
// ("no CIDRs granted" is a real, meaningful state, not a loading state) — so this always renders
// *something* rather than leaving a blank cell the operator might mistake for "still loading".
function scopeList(v: unknown): string {
  if (Array.isArray(v)) return v.length ? v.map(String).join(", ") : "none";
  if (typeof v === "string" && v) return v;
  return "—";
}

function ScopeDetail({ engagement }: { engagement: Engagement | undefined }) {
  if (!engagement) return <div className="scope-detail dim">no engagement selected</div>;

  // `scope` is typed loosely (see api.ts) so an older control-plane build still type-checks; read
  // every field defensively rather than assuming the widened shape has landed.
  const scope = (engagement.scope || {}) as Record<string, unknown>;
  const maxIntensity =
    typeof scope.max_intensity === "string" || typeof scope.max_intensity === "number" ? String(scope.max_intensity) : "—";
  const windowEnd = typeof scope.not_after === "string" && scope.not_after ? scope.not_after : "no expiry";
  const flags: string[] = [];
  if (scope.allow_exploit) flags.push("exploit");
  if (scope.allow_credential_attacks) flags.push("credential attacks");

  return (
    <div className="scope-detail">
      <div className="scope-detail-row">
        <span className="dim">CIDRs</span>
        <span className="mono">{scopeList(scope.allowed_cidrs)}</span>
      </div>
      <div className="scope-detail-row">
        <span className="dim">Domains</span>
        <span className="mono">{scopeList(scope.allowed_domains)}</span>
      </div>
      <div className="scope-detail-row">
        <span className="dim">Artifacts</span>
        <span className="mono">{scopeList(scope.allowed_artifacts)}</span>
      </div>
      <div className="scope-detail-row">
        <span className="dim">Max intensity</span>
        <span className="mono">{maxIntensity}</span>
      </div>
      <div className="scope-detail-row">
        <span className="dim">Window end</span>
        <span className="mono">{windowEnd}</span>
      </div>
      <div className="scope-detail-row">
        <span className="dim">Offensive flags granted</span>
        <span>
          {flags.length ? (
            flags.map((f) => (
              <span className="tag" key={f}>
                {f}
              </span>
            ))
          ) : (
            <span className="dim">none</span>
          )}
        </span>
      </div>
    </div>
  );
}

// The persona picker. It used to be a `.tool-lib` trigger + dropdown living inline in the old
// "Objective & scope" card; here it renders directly inside an already-open panel section, so there
// is no need for a second nested expand/collapse layer — the operator opened the gear for exactly
// this. Per the redesign spec (§4), a persona is identified by its label and stage only: no glyph,
// no accent color, anywhere.
function PersonaSection({
  profiles,
  activeId,
  onChange,
}: {
  profiles: Profile[];
  activeId: string;
  onChange: (id: string) => void;
}) {
  if (profiles.length === 0) return <div className="dim">loading personas…</div>;
  const active = resolveProfile(profiles, activeId);

  return (
    <div className="persona-menu">
      {profiles.map((p) => (
        <label key={p.id} className={`persona-option${p.id === active?.id ? " selected" : ""}`}>
          <input type="radio" name="persona" checked={p.id === active?.id} onChange={() => onChange(p.id)} />
          <span>
            <b>{p.label}</b>
            {p.stage && <span className="dim"> · {p.stage}</span>}
            {p.orchestrator && <span className="dim"> · orchestrator</span>}
            {p.generalist && <span className="dim"> · generalist</span>}
            {p.gated_flag && <span className="tag">scope-gated</span>}
          </span>
          <span className="dim">{p.tagline}</span>
        </label>
      ))}
    </div>
  );
}

// The "tool library": a dropdown scoped to the active persona's exact tool list — nothing that
// persona can't reach is ever offered, so unchecking is a pure narrowing within an already-narrow
// set. The orchestrator has no tools of its own (it delegates to the crew), so its dropdown falls
// back to the full registry grouped by the specialist that owns each tool. When the persona roster
// hasn't loaded at all (no `/profiles`, or an older API), this degrades to the old stage-grouped,
// all-tools behaviour so nothing regresses for a pre-persona backend. Moved here verbatim from
// page.tsx (same behaviour, same classes) minus the persona glyph in the owner-group labels.
function ToolLibrary({
  tools,
  enabled,
  onChange,
  activeProfile,
  profiles,
}: {
  tools: Tool[];
  enabled: Set<string> | null;
  onChange: (next: Set<string>) => void;
  activeProfile: Profile | undefined;
  profiles: Profile[];
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  // Close on outside click or Esc while open — same pattern as the panel itself, one level down.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // The tools actually available to pick from — scoped to the active persona (see toolsForPersona
  // above), not the full registry. `page.tsx` resets `enabled` to exactly this set whenever the
  // persona changes, but we still intersect defensively here in case stale state ever lingers.
  const available = toolsForPersona(activeProfile, tools);
  const availableNames = new Set(available.map((t) => t.name));
  const sel = enabled ? new Set([...enabled].filter((n) => availableNames.has(n))) : new Set(availableNames);
  const total = available.length;
  const count = sel.size;

  // Grouping strategy: a specific (non-orchestrator) persona's toolkit is small and already fully
  // scoped, so it renders as one flat list. The orchestrator spans the whole registry, so it groups
  // by owning persona instead. No roster at all falls back to the legacy stage grouping.
  const noRoster = profiles.length === 0;
  const groupByOwner = !!activeProfile?.orchestrator;

  type Group = { title: string | null; items: Tool[] };
  let groups: Group[];
  if (groupByOwner) {
    const owners = profiles.filter((p) => !p.orchestrator);
    const owned = new Set<string>();
    groups = owners
      .map((p) => {
        const items = available.filter((t) => p.tools.includes(t.name));
        items.forEach((t) => owned.add(t.name));
        return { title: p.label, items };
      })
      .filter((g) => g.items.length > 0);
    const unassigned = available.filter((t) => !owned.has(t.name));
    if (unassigned.length > 0) groups.push({ title: "Unassigned", items: unassigned });
  } else if (noRoster) {
    groups = FALLBACK_STAGES.map((stage) => ({
      title: stage,
      items: available.filter((t) => (t.stage || stageOf(t.name)) === stage),
    })).filter((g) => g.items.length > 0);
  } else {
    groups = [{ title: null, items: available }];
  }

  const toggle = (name: string) => {
    const next = new Set(sel);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    onChange(next);
  };
  const selectAll = () => onChange(new Set(availableNames));
  const selectNone = () => onChange(new Set());

  const label =
    total === 0
      ? "loading…"
      : count === total
      ? `All tools · ${total}`
      : count === 0
      ? "No tools selected"
      : `${count} of ${total} tools`;

  // The section header per spec: "<Label>'s toolkit · N tools" for a specific persona; kept at
  // parity with today's own variants for the orchestrator and no-roster cases.
  const menuHeader =
    activeProfile && !activeProfile.orchestrator
      ? `${activeProfile.label}'s toolkit · ${total} tool${total === 1 ? "" : "s"}`
      : activeProfile?.orchestrator
      ? `${activeProfile.label}'s toolkit · ${total} tool${total === 1 ? "" : "s"} · grouped by specialist`
      : "Enable tools for this run";

  return (
    <>
      <h4>{menuHeader}</h4>
      <div className="tool-lib" ref={ref}>
        <button type="button" className="tool-lib-trigger" onClick={() => setOpen((o) => !o)} disabled={total === 0} aria-expanded={open}>
          <span>{label}</span>
          <span className="dim" aria-hidden>
            ▾
          </span>
        </button>
        {open && (
          <div className="tool-menu">
            <div className="tool-menu-head">
              <span className="dim">{menuHeader}</span>
              <span>
                <button type="button" className="mini-btn" onClick={selectAll}>
                  All
                </button>
                <button type="button" className="mini-btn" onClick={selectNone}>
                  None
                </button>
              </span>
            </div>
            <div className="tool-menu-body">
              {groups.map((g, i) => (
                <div className="tool-group" key={g.title ?? `flat-${i}`}>
                  {g.title && <div className="tool-group-title">{g.title}</div>}
                  {g.items.map((t) => (
                    <label className="tool-row" key={t.name} title={t.description}>
                      <input type="checkbox" checked={sel.has(t.name)} onChange={() => toggle(t.name)} />
                      <span className="mono tool-name">{t.name}</span>
                      {t.requires_flag && <span className="tag">scope-gated</span>}
                      {t.mcp && <span className="tag">mcp</span>}
                    </label>
                  ))}
                </div>
              ))}
            </div>
            {count === 0 && (
              <div className="tool-menu-foot dim">No tools selected — the run will fall back to this persona's default toolkit.</div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

export default function ControlPanel(props: ControlPanelProps) {
  const {
    open,
    onClose,
    engagements,
    selected,
    onSelectEngagement,
    activeEngagement,
    guardEnabled,
    guardBusy,
    guardStatus,
    onToggleGuard,
    profiles,
    profile,
    onProfileChange,
    tools,
    enabled,
    onEnabledChange,
    target,
    onTargetChange,
    objective,
    onObjectiveChange,
    onLaunch,
    busy,
    status,
  } = props;

  const ref = useRef<HTMLDivElement | null>(null);

  // Close on outside click or Escape — the exact pattern today's ToolLibrary/PersonaPicker dropdowns
  // already use in page.tsx, just anchored to the whole panel rather than one field's menu.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  if (!open) return null;

  const activeProfile = resolveProfile(profiles, profile);

  return (
    <div className="control-panel" ref={ref}>
      <div className="control-panel-section">
        <h4>Engagement</h4>
        <div className="field">
          <EngagementPicker engagements={engagements} selected={selected} onSelect={onSelectEngagement} />
        </div>
      </div>

      <div className="control-panel-section">
        <h4>Scope</h4>
        <ScopeDetail engagement={activeEngagement} />
      </div>

      <div className="control-panel-section">
        <h4>Scope guard</h4>
        <div className={`control-guard${guardEnabled ? "" : " off"}`}>
          <label>
            <input type="checkbox" checked={guardEnabled} disabled={guardBusy} onChange={onToggleGuard} />
            Scope guard {guardEnabled ? "enabled" : "disabled"}
          </label>
          {guardStatus && <div className="dim">{guardStatus}</div>}
          <div className="dim">Disabling requires an admin key.</div>
        </div>
      </div>

      <div className="control-panel-section">
        <h4>Personality</h4>
        <PersonaSection profiles={profiles} activeId={profile} onChange={onProfileChange} />
        {activeProfile && <div className="dim">{activeProfile.tagline}</div>}
      </div>

      <div className="control-panel-section">
        <ToolLibrary tools={tools} enabled={enabled} onChange={onEnabledChange} activeProfile={activeProfile} profiles={profiles} />
      </div>

      <div className="control-panel-section">
        <div className="field">
          <label>Seed target (IP / host / URL)</label>
          <input className="input" value={target} onChange={(e) => onTargetChange(e.target.value)} placeholder="10.0.0.5" />
        </div>
        <div className="field">
          <label>Objective</label>
          <textarea
            className="textarea"
            rows={3}
            value={objective}
            onChange={(e) => onObjectiveChange(e.target.value)}
            placeholder="What should the agent focus on? (guidance only)"
          />
        </div>
        <button className="btn btn-primary" onClick={onLaunch} disabled={busy || !selected || !target.trim()}>
          Launch
        </button>
        {status && <div className="dim">{status}</div>}
      </div>
    </div>
  );
}
