"use client";
// Dashboard: KPI cards, severity breakdown, correlated attack chains, and the current-issues
// table for the selected engagement. Actions: validate corroborated findings, download the report.
import { useEffect, useState } from "react";
import {
  fetchChains, fetchMetrics, queryFindings, reportUrl, validateFindings,
  type Chain, type Finding, type Metrics,
} from "../../lib/api";
import { useEngagement } from "../../lib/useEngagement";
import EngagementPicker from "../EngagementPicker";
import { Callout, EmptyState, Kpi, SectionTitle, SeverityBadge, SEV_COLOR, SEV_ORDER } from "../ui";

export default function Dashboard() {
  const { engagements, selected, select } = useEngagement();
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [issues, setIssues] = useState<Finding[]>([]);
  const [chains, setChains] = useState<Chain[]>([]);
  const [note, setNote] = useState("");

  useEffect(() => {
    if (!selected) {
      setMetrics(null);
      setIssues([]);
      setChains([]);
      return;
    }
    const load = () => {
      fetchMetrics(selected).then(setMetrics).catch(() => setMetrics(null));
      queryFindings(selected, { limit: "50" }).then(setIssues).catch(() => setIssues([]));
      fetchChains(selected).then(setChains).catch(() => setChains([]));
    };
    load();
    const t = setInterval(load, 5000); // live refresh while scans run
    return () => clearInterval(t);
  }, [selected]);

  async function onValidate() {
    if (!selected) return;
    setNote("validating…");
    try {
      const { promoted } = await validateFindings(selected);
      setNote(promoted ? `${promoted} finding(s) promoted to confirmed` : "no corroborated findings to promote");
    } catch (e) {
      setNote(`error: ${String(e)}`);
    }
  }

  const sev = metrics?.findings_by_severity || {};
  const sevMax = Math.max(1, ...SEV_ORDER.map((k) => sev[k] || 0));

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p className="page-sub">Live KPIs, severity breakdown, and correlated attack chains for the selected engagement.</p>
        </div>
        <div className="row">
          <EngagementPicker engagements={engagements} selected={selected} onSelect={select} />
          {selected && (
            <>
              <button className="btn" onClick={onValidate}>Validate findings</button>
              <a className="btn btn-primary" href={reportUrl(selected)} target="_blank" rel="noreferrer">
                Report ↗
              </a>
            </>
          )}
        </div>
      </div>

      {!selected && (
        <div style={{ marginTop: 20 }}>
          <Callout>Select an engagement to view its metrics, or create one on the Network Map.</Callout>
        </div>
      )}
      {note && (
        <div className="muted" style={{ marginTop: 12, fontSize: 13 }}>{note}</div>
      )}

      {metrics && (
        <>
          <div className="row" style={{ margin: "20px 0", gap: 14 }}>
            <Kpi label="CVEs identified" value={metrics.cves_identified} accent="var(--high)" />
            <Kpi label="Exposed endpoints" value={metrics.exposed_endpoints} accent="var(--medium)" />
            <Kpi label="Hosts discovered" value={metrics.hosts} accent="var(--low)" />
            <Kpi label="Open issues" value={metrics.open_issues} accent="var(--brand)" />
            <Kpi label="Runs" value={metrics.runs} accent="var(--ok)" />
          </div>

          <SectionTitle>Findings by severity</SectionTitle>
          <div className="card card-pad" style={{ maxWidth: 620 }}>
            <div className="stack" style={{ gap: 9 }}>
              {SEV_ORDER.map((s) => {
                const count = sev[s] || 0;
                return (
                  <div key={s} className="row" style={{ gap: 12, flexWrap: "nowrap" }}>
                    <span style={{ width: 68, color: "var(--text-muted)", fontSize: 13, textTransform: "capitalize" }}>{s}</span>
                    <div style={{ flex: 1, background: "var(--surface-3)", borderRadius: 5, overflow: "hidden", height: 18 }}>
                      <div
                        style={{
                          width: `${(count / sevMax) * 100}%`,
                          minWidth: count ? 22 : 0,
                          height: "100%",
                          background: SEV_COLOR[s],
                          borderRadius: 5,
                          transition: "width 0.4s ease",
                        }}
                      />
                    </div>
                    <span style={{ width: 30, textAlign: "right", fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {chains.length > 0 && (
        <>
          <SectionTitle>Attack chains</SectionTitle>
          <div className="row" style={{ gap: 12, alignItems: "stretch" }}>
            {chains.slice(0, 6).map((c, i) => (
              <div key={c.id || i} className="card card-pad" style={{ minWidth: 240, flex: 1 }}>
                <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
                  <strong style={{ fontSize: 14 }}>{c.title || c.name || `Chain ${i + 1}`}</strong>
                  {c.severity && <SeverityBadge severity={String(c.severity)} />}
                </div>
                <div className="dim" style={{ fontSize: 12.5 }}>
                  {Array.isArray(c.steps) ? `${c.steps.length} step(s)` : "correlated finding path"}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <SectionTitle>Current issues</SectionTitle>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>Target</th>
              <th>CVE</th>
              <th>State</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            {issues.map((f) => (
              <tr key={f.dedup_key}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td>{f.title}</td>
                <td className="mono">{f.target}</td>
                <td className="mono">{f.cve || "—"}</td>
                <td><span className="badge pill">{f.state}</span></td>
                <td className="mono">{f.times_seen}×</td>
              </tr>
            ))}
            {issues.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState>{selected ? "No findings yet — launch a run to populate this table." : "Select an engagement."}</EmptyState>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </main>
  );
}
