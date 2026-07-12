"use client";
// Query view: structured finding filters plus a read-only Cypher box against the graph.
import { useState } from "react";
import { queryFindings, runCypher, type Finding } from "../../lib/api";
import { useEngagement } from "../../lib/useEngagement";
import EngagementPicker from "../EngagementPicker";
import { Callout, EmptyState, SectionTitle, SeverityBadge } from "../ui";

const EXAMPLES = [
  "MATCH (i:IP)<-[:AFFECTS]-(f:Finding) RETURN i.address, f.title LIMIT 25",
  "MATCH (h:IP)-[:HAS_PORT]->(p:Port) RETURN h.address, p.number LIMIT 50",
  "MATCH (f:Finding) WHERE f.severity = 'critical' RETURN f.title, f.cve LIMIT 25",
];

export default function QueryPage() {
  const { engagements, selected, select } = useEngagement();
  const [severity, setSeverity] = useState("");
  const [text, setText] = useState("");
  const [results, setResults] = useState<Finding[]>([]);
  const [searched, setSearched] = useState(false);
  const [cypher, setCypher] = useState(EXAMPLES[0]);
  const [rows, setRows] = useState<Record<string, unknown>[]>([]);
  const [ranGraph, setRanGraph] = useState(false);
  const [err, setErr] = useState("");

  async function runFilters() {
    if (!selected) return;
    const params: Record<string, string> = { limit: "200" };
    if (severity) params.severity = severity;
    if (text) params.q = text;
    setResults(await queryFindings(selected, params));
    setSearched(true);
  }

  async function runGraph() {
    if (!selected) return;
    setErr("");
    try {
      const res = await runCypher(selected, cypher);
      setRows(res.rows);
      setRanGraph(true);
    } catch (e) {
      setErr(String(e));
      setRows([]);
      setRanGraph(true);
    }
  }

  const cols = rows[0] ? Object.keys(rows[0]) : [];

  return (
    <main className="page">
      <div className="page-head">
        <div>
          <h1>Query</h1>
          <p className="page-sub">Filter normalized findings, or run read-only Cypher directly against the knowledge graph.</p>
        </div>
        <EngagementPicker engagements={engagements} selected={selected} onSelect={select} />
      </div>

      {!selected && (
        <div style={{ marginTop: 18 }}>
          <Callout>Select an engagement to query its findings and graph.</Callout>
        </div>
      )}

      <SectionTitle>Findings filter</SectionTitle>
      <div className="card card-pad">
        <div className="row" style={{ alignItems: "flex-end" }}>
          <div className="field" style={{ minWidth: 150 }}>
            <label>Severity</label>
            <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">any severity</option>
              {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="field" style={{ flex: 1, minWidth: 220 }}>
            <label>Text in title / evidence</label>
            <input className="input" placeholder="e.g. tls, sql, open port" value={text} onChange={(e) => setText(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={runFilters} disabled={!selected}>Search</button>
        </div>
      </div>

      <div className="table-wrap" style={{ marginTop: 14 }}>
        <table className="data">
          <thead>
            <tr><th>Severity</th><th>Title</th><th>Target</th><th>CVE</th><th>Tool</th></tr>
          </thead>
          <tbody>
            {results.map((f) => (
              <tr key={f.dedup_key}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td>{f.title}</td>
                <td className="mono">{f.target}</td>
                <td className="mono">{f.cve || "—"}</td>
                <td className="mono">{f.source_tool}</td>
              </tr>
            ))}
            {results.length === 0 && (
              <tr><td colSpan={5}><EmptyState>{searched ? "No matching findings." : "Run a search to see findings."}</EmptyState></td></tr>
            )}
          </tbody>
        </table>
      </div>

      <SectionTitle>Graph query · read-only Cypher</SectionTitle>
      <div className="card card-pad">
        <textarea className="textarea" value={cypher} onChange={(e) => setCypher(e.target.value)} spellCheck={false} />
        <div className="row" style={{ marginTop: 10, justifyContent: "space-between" }}>
          <div className="row" style={{ gap: 6 }}>
            <span className="dim" style={{ fontSize: 12 }}>examples:</span>
            {EXAMPLES.map((q, i) => (
              <button key={i} className="tag" style={{ cursor: "pointer" }} onClick={() => setCypher(q)}>
                {i === 0 ? "affects" : i === 1 ? "ports" : "critical"}
              </button>
            ))}
          </div>
          <button className="btn btn-primary" onClick={runGraph} disabled={!selected}>Run query</button>
        </div>
        {err && (
          <div style={{ marginTop: 10 }}>
            <Callout kind="danger">{err}</Callout>
          </div>
        )}
      </div>

      {(rows.length > 0 || (ranGraph && !err)) && (
        <div className="table-wrap" style={{ marginTop: 14 }}>
          <table className="data">
            <thead>
              <tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>{cols.map((c) => <td key={c} className="mono">{JSON.stringify(r[c])}</td>)}</tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={Math.max(1, cols.length)}><EmptyState>Query returned no rows.</EmptyState></td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
