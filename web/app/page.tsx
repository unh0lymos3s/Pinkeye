"use client";
// Landing page: pick/launch an engagement, launch a run, or head straight to the knowledge graph.
// Deliberately minimal — no title, no banner, just three centered controls. Detail forms stay
// collapsed until clicked so the page reads as a launcher, not a form.
import { useState } from "react";
import Link from "next/link";
import AsciiBanner from "./AsciiBanner";
import EngagementPicker from "./EngagementPicker";
import EyeOrb from "./EyeOrb";
import { createEngagement, createRun, updateScopeGuard } from "../lib/api";
import { useEngagement } from "../lib/useEngagement";
import { useLastRun } from "../lib/useLastRun";

const SCAN_TOOLS = ["nmap", "nikto", "nuclei", "ffuf", "tls_cert", "cve_lookup"];
const INTENSITIES = ["light", "normal", "aggressive"];

export default function Home() {
  const { engagements, selected, select, refresh } = useEngagement();
  const { setLastRunId } = useLastRun(selected);
  const [name, setName] = useState("lab-engagement");
  const [cidrs, setCidrs] = useState("10.0.0.0/24");
  // Scope guard defaults ON — this is an opt-in bypass, never a default-off setting, so a form the
  // operator submits without touching this checkbox produces the same fully-guarded engagement it
  // always has.
  const [scopeGuard, setScopeGuard] = useState(true);
  const [target, setTarget] = useState("10.0.0.5");
  const [mode, setMode] = useState<"scan" | "agent">("scan");
  const [tool, setTool] = useState("nmap");
  const [intensity, setIntensity] = useState("light");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [engOpen, setEngOpen] = useState(false);
  const [runOpen, setRunOpen] = useState(false);
  // Toggling the guard on an *existing* engagement is a separate action from the create form
  // above (disabling requires an admin key); tracked independently so it can show its own busy/
  // error state without disturbing the create-engagement fields.
  const [guardBusy, setGuardBusy] = useState(false);
  const [guardStatus, setGuardStatus] = useState("");

  const activeEngagement = engagements.find((e) => e.id === selected);
  // Absent `scope` (older control-plane build, or an engagement created before this shipped)
  // means the guard is on — that is the documented server-side default.
  const guardEnabled = activeEngagement?.scope?.scope_guard_enabled ?? true;

  async function onCreate() {
    if (!name.trim()) return;
    setBusy(true);
    setStatus("creating engagement…");
    try {
      const eng = await createEngagement({
        name: name.trim(),
        allowed_cidrs: cidrs.split(",").map((s) => s.trim()).filter(Boolean),
        allowed_domains: [],
        scope_guard_enabled: scopeGuard,
      });
      await refresh();
      select(eng.id);
      setStatus(`engagement "${eng.name}" created`);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

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

  async function onScan() {
    if (!selected) return;
    setBusy(true);
    setStatus(mode === "agent" ? "launching agent run (scope-checked)…" : "launching scan (scope-checked)…");
    try {
      const run = await createRun(selected, { target, tool, intensity, mode });
      setLastRunId(run.id);
      setStatus(`run ${run.id.slice(0, 8)} — ${run.status}`);
    } catch (e) {
      setStatus(`error: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="launcher">
      <AsciiBanner />

      <div className="launcher-row">
        <div className={`toggle-box${engOpen ? " open" : ""}`} onClick={() => setEngOpen((o) => !o)}>
          <span className="toggle-box-icon">◆</span>
          <span className="toggle-box-label">Engagement</span>
        </div>

        <Link href="/map" className="eye-btn">
          <EyeOrb />
        </Link>

        <div className={`toggle-box${runOpen ? " open" : ""}`} onClick={() => setRunOpen((o) => !o)}>
          <span className="toggle-box-icon">▶</span>
          <span className="toggle-box-label">Launch run</span>
        </div>
      </div>

      {(engOpen || runOpen) && (
        <div className="toggle-panel">
          {engOpen && (
            <div className="card card-pad">
              <div className="row" style={{ alignItems: "flex-end" }}>
                <div className="field" style={{ minWidth: 200 }}>
                  <label>Active engagement</label>
                  <EngagementPicker engagements={engagements} selected={selected} onSelect={select} />
                </div>
                <div className="field" style={{ flex: 1, minWidth: 180 }}>
                  <label>New engagement name</label>
                  <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="lab-engagement" />
                </div>
                <div className="field" style={{ flex: 1, minWidth: 180 }}>
                  <label>Allowed CIDRs (comma-separated)</label>
                  <input className="input" value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="10.0.0.0/24" />
                </div>
                <div className="field">
                  <label>Scope guard</label>
                  <label className="scope-guard-check" title="Off means every target is treated as in-scope for this engagement — an opt-in bypass, not a default.">
                    <input type="checkbox" checked={scopeGuard} onChange={(e) => setScopeGuard(e.target.checked)} />
                    {scopeGuard ? "On" : "Off — every target authorized"}
                  </label>
                </div>
                <button className="btn" onClick={onCreate} disabled={busy || !name.trim()}>
                  Create
                </button>
              </div>
              {selected && (
                <div className="scope-guard-row">
                  <span className={`scope-guard-pill${guardEnabled ? "" : " off"}`}>
                    {guardEnabled ? "🛡 scope guard on" : "⚠ scope guard disabled"}
                  </span>
                  <span className="dim" style={{ fontSize: 12.5 }}>
                    for <b>{activeEngagement?.name || selected}</b>
                  </span>
                  <button className="mini-btn" onClick={onToggleGuard} disabled={guardBusy}>
                    {guardBusy ? "…" : guardEnabled ? "Disable (admin)" : "Re-enable"}
                  </button>
                  {guardStatus && (
                    <span className="dim" style={{ fontSize: 12 }}>
                      {guardStatus}
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          {runOpen && (
            <div className="card card-pad">
              <div className="row" style={{ alignItems: "flex-end" }}>
                <div className="field" style={{ flex: 1, minWidth: 200 }}>
                  <label>Target (IP / host / URL)</label>
                  <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.0.0.5" />
                </div>
                <div className="field" style={{ minWidth: 150 }}>
                  <label>Mode</label>
                  <select className="select" value={mode} onChange={(e) => setMode(e.target.value as "scan" | "agent")}>
                    <option value="scan">Scan — one tool</option>
                    <option value="agent">Agent — LLM plans</option>
                  </select>
                </div>
                {mode === "scan" && (
                  <>
                    <div className="field" style={{ minWidth: 140 }}>
                      <label>Tool</label>
                      <select className="select" value={tool} onChange={(e) => setTool(e.target.value)}>
                        {SCAN_TOOLS.map((t) => (
                          <option key={t} value={t}>{t}</option>
                        ))}
                      </select>
                    </div>
                    <div className="field" style={{ minWidth: 130 }}>
                      <label>Intensity</label>
                      <select className="select" value={intensity} onChange={(e) => setIntensity(e.target.value)}>
                        {INTENSITIES.map((i) => (
                          <option key={i} value={i}>{i}</option>
                        ))}
                      </select>
                    </div>
                  </>
                )}
                <button className="btn btn-primary" onClick={onScan} disabled={busy || !selected}>
                  {mode === "agent" ? "Run agent" : `Run ${tool}`}
                </button>
              </div>
              {status && (
                <div className="muted" style={{ marginTop: 12, fontSize: 13 }}>
                  {status}
                </div>
              )}
              {!selected && (
                <div className="dim" style={{ marginTop: 12, fontSize: 13 }}>
                  Select or create an engagement above to enable runs.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </main>
  );
}
