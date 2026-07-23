// In-app user guide. A single scrollable reference covering safety, the workflow, each view,
// the tool catalog, and troubleshooting — so operators don't have to leave the UI to learn it.
import Link from "next/link";
import { Callout, SectionTitle } from "../ui";
import { API_BASE } from "../../lib/api";

export const metadata = { title: "Guide · Pinkeye" };

const TOOLS: { name: string; kind: string; what: string; gated?: boolean }[] = [
  { name: "nmap", kind: "Recon", what: "Host discovery and port/service scanning." },
  { name: "tls_cert", kind: "Recon", what: "TLS certificate and configuration inspection." },
  { name: "cve_lookup", kind: "Intel", what: "Offline CVE match for a product/version (seeded DB)." },
  { name: "nikto", kind: "DAST", what: "Web server misconfiguration and known-issue scan." },
  { name: "nuclei", kind: "DAST", what: "Templated vulnerability checks against web targets." },
  { name: "ffuf", kind: "DAST", what: "Content/endpoint discovery via fuzzing." },
  { name: "zap", kind: "DAST", what: "Authenticated web app scanning (supports an auth profile)." },
  { name: "semgrep", kind: "SAST", what: "Static analysis over authorized source artifacts." },
  { name: "gitleaks", kind: "SAST", what: "Secret scanning in repositories." },
  { name: "trivy", kind: "SAST", what: "Dependency and container vulnerability scanning." },
  { name: "virustotal", kind: "Reputation", what: "File/URL reputation (needs VT_API_KEY)." },
  { name: "credential_attack", kind: "Intrusive", what: "Hydra, hard-capped. Requires allow_credential_attacks.", gated: true },
  { name: "exploit / post_exploit", kind: "Intrusive", what: "Metasploit, defaults to non-destructive check. Requires allow_exploit.", gated: true },
];

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start", gap: 14, marginBottom: 16 }}>
      <div
        style={{
          flex: "none", width: 30, height: 30, borderRadius: 8, display: "grid", placeItems: "center",
          background: "var(--brand-soft)", color: "var(--brand)", fontWeight: 700, fontSize: 14,
          boxShadow: "inset 0 0 0 1px var(--brand-ring)",
        }}
      >
        {n}
      </div>
      <div>
        <div style={{ fontWeight: 600, marginBottom: 3 }}>{title}</div>
        <div className="muted" style={{ fontSize: 13.5 }}>{children}</div>
      </div>
    </div>
  );
}

export default function Guide() {
  return (
    <main className="page" style={{ maxWidth: 880 }}>
      <div className="page-head">
        <div>
          <h1>User Guide</h1>
          <p className="page-sub">
            How Pinkeye works and how to drive it — from a scoped engagement to a finished report.
          </p>
        </div>
      </div>

      <div style={{ marginTop: 16 }}>
        <Callout kind="danger">
          <strong>Authorized use only.</strong> Run only against assets you own or are contracted to test.
          Every run is bound to a <strong>signed scope</strong> the harness enforces in code before any tool
          executes. Intrusive capabilities (exploitation, credential attacks) stay off unless explicitly
          authorized in that scope.
        </Callout>
      </div>

      <SectionTitle>What this is</SectionTitle>
      <p className="muted">
        Pinkeye is an AI-assisted DAST/SAST vulnerability-assessment and red-team harness. A
        deterministic control plane wraps a swappable LLM so tool execution, sandbox isolation, scope
        enforcement, scoring, and correlation stay reliable regardless of which model is plugged in. The
        LLM plans and triages; the harness keeps it safe, reproducible, and auditable. Findings are
        rendered as a knowledge graph, summarized in a dashboard, queryable via filters or Cypher, and
        exported as a Markdown report.
      </p>

      <SectionTitle>The workflow</SectionTitle>
      <div className="card card-pad">
        <Step n={1} title="Create a scoped engagement">
          On the <Link href="/" className="tag" style={{ textDecoration: "none" }}>Home</Link> page, give the
          engagement a name and the CIDRs (and domains) you're authorized to test. The scope is signed at
          creation and becomes the authorization boundary for every run.
        </Step>
        <Step n={2} title="Launch a run">
          Pick a target and choose a mode. <strong>Scan</strong> runs a single tool deterministically at a
          chosen intensity. <strong>Agent</strong> lets the LLM plan multi-step recon and scanning across all
          authorized tools. The scope guard checks the target before anything executes — out-of-scope targets
          are hard-rejected and logged.
        </Step>
        <Step n={3} title="Watch the graph fill in">
          Open <Link href="/map" className="tag" style={{ textDecoration: "none" }}>the Map</Link> (via the eye
          button on the Home page) to watch hosts, ports, services, and findings appear as connected nodes and
          refresh live. Toggle <em>full map</em> for a cross-engagement overview.
        </Step>
        <Step n={4} title="Review on the dashboard">
          The <Link href="/dashboard" className="tag" style={{ textDecoration: "none" }}>Dashboard</Link> shows
          KPIs, the severity breakdown, correlated attack chains, and the current-issues table. Use
          <strong> Validate findings</strong> to promote results corroborated across independent runs from
          suspected to confirmed.
        </Step>
        <Step n={5} title="Query and report">
          Use <Link href="/query" className="tag" style={{ textDecoration: "none" }}>Query</Link> to filter
          findings or run read-only Cypher. Download the Markdown report (CVSS + ATT&CK) from the dashboard.
        </Step>
      </div>

      <SectionTitle>Scope &amp; safety model</SectionTitle>
      <ul className="muted" style={{ paddingLeft: 20, lineHeight: 1.8 }}>
        <li>Scopes are <strong>HMAC-signed</strong> at creation; the guard verifies the signature and the target on every run.</li>
        <li>Tools run inside a <strong>sandbox</strong>. For real targets, harden with <code className="k">EYE_SANDBOX_RUNTIME=runsc</code> (gVisor) and an egress enforcer.</li>
        <li>Intrusive tools are off by default. They require an explicit <code className="k">allow_exploit</code> / <code className="k">allow_credential_attacks</code> flag, baked into the signature.</li>
        <li>Every action is written to an <strong>audit log</strong>; findings are deduplicated with a <code className="k">times_seen</code> counter for replay integrity.</li>
      </ul>

      <SectionTitle>Run modes</SectionTitle>
      <div className="row" style={{ gap: 14, alignItems: "stretch" }}>
        <div className="card card-pad" style={{ flex: 1, minWidth: 240 }}>
          <strong>Scan</strong>
          <p className="muted" style={{ fontSize: 13.5, marginTop: 6 }}>
            One tool, one target, chosen intensity (<code className="k">light</code> → <code className="k">aggressive</code>,
            capped by the engagement's max intensity). Deterministic and repeatable — best for a targeted check.
          </p>
        </div>
        <div className="card card-pad" style={{ flex: 1, minWidth: 240 }}>
          <strong>Agent</strong>
          <p className="muted" style={{ fontSize: 13.5, marginTop: 6 }}>
            The LLM plans a multi-step assessment across all authorized tools, triaging as it goes. The harness
            still enforces scope and gating on each tool call — the model can't step outside the boundary.
          </p>
        </div>
      </div>

      <SectionTitle>Running an assessment: code → dynamic → exploitation</SectionTitle>
      <p className="muted" style={{ marginBottom: 4 }}>
        The recommended path is <strong>Agent</strong> mode on the{" "}
        <Link href="/agent" className="tag" style={{ textDecoration: "none" }}>Agent Chat</Link> page. Use the{" "}
        <strong>Tools</strong> dropdown there to enable exactly the tools for the phase you want — the pipeline
        rail dims the phases you switch off — then set the target and launch. The agent runs non-intrusive
        phases on its own and <strong>pauses to ask you in the chat</strong> before anything intrusive.
      </p>

      <div className="card card-pad" style={{ marginTop: 8 }}>
        <Step n={1} title="Code analysis (SAST) — scan source, dependencies, and secrets">
          Point the target at an <strong>authorized source artifact</strong> — a repository path or checkout
          mounted for the harness (the pooled Snyk-backed scanner reads from <code className="k">EYE_SRC_ROOT</code>).
          In the Tools dropdown keep the <span className="badge pill">SAST</span> tools enabled:{" "}
          <code className="k">semgrep</code> (static code analysis for injection, authz, and unsafe APIs),{" "}
          <code className="k">gitleaks</code> (committed secrets and keys), and <code className="k">trivy</code>{" "}
          (vulnerable dependencies and container CVEs). These act on artifacts, not the network, so they run
          without touching a live host. Findings land in the graph and dashboard like any other.
        </Step>
        <Step n={2} title="Dynamic analysis (DAST) — probe the running target">
          Set the target to a reachable host or URL. The agent starts with recon —{" "}
          <code className="k">nmap</code> for ports/services and <code className="k">tls_cert</code> for
          transport hygiene — then runs the <span className="badge pill">DAST</span> tools against what it
          finds: <code className="k">nikto</code> (server misconfig), <code className="k">nuclei</code>{" "}
          (templated CVE/misconfig checks), and <code className="k">ffuf</code> (content/endpoint discovery).
          For app surface behind a login, enable <code className="k">zap</code> and attach an{" "}
          <strong>auth profile</strong> on launch (a header/token that resolves from secrets, never stored in
          the run). Raise <em>intensity</em> from <code className="k">light</code> toward{" "}
          <code className="k">aggressive</code> only within the engagement's cap.
        </Step>
        <Step n={3} title="Move to exploitation — gated, and only with your approval">
          Exploitation and credential attacks stay off unless the engagement's <strong>signed scope</strong>{" "}
          carries the matching flag (<code className="k">allow_exploit</code> /{" "}
          <code className="k">allow_credential_attacks</code>). When those are authorized and the agent finds a
          candidate, it will <strong>stop and ask you in the chat</strong> before acting —{" "}
          <code className="k">exploit</code> / <code className="k">post_exploit</code> (Metasploit, defaulting
          to a non-destructive check) and <code className="k">credential_attack</code> (Hydra, hard-capped).
          Approve to proceed, deny to keep it to non-intrusive steps. Confirmed results feed the attack-chain
          correlation on the dashboard.
        </Step>
      </div>

      <SectionTitle>Talking to the agent (permissions &amp; recommendations)</SectionTitle>
      <p className="muted" style={{ marginBottom: 10 }}>
        The Agent Chat is a two-way conversation. The agent streams its reasoning, tool calls, and findings,
        and when it needs you it posts a prompt and <strong>waits</strong> — the reply box under the transcript
        lights up. There are three kinds of prompt:
      </p>
      <ul className="muted" style={{ paddingLeft: 20, lineHeight: 1.8 }}>
        <li>
          <strong>🔒 Permission</strong> — an approve/deny gate the agent must clear before any intrusive step.
          Use the <strong>Approve</strong> / <strong>Deny</strong> buttons, or type a specific instruction.
        </li>
        <li>
          <strong>💡 Recommendation</strong> — the agent proposes a next action and asks you to steer. Reply to
          redirect it, or approve its suggestion.
        </li>
        <li>
          <strong>❔ Question</strong> — anything else it needs (a credential hint, which host to prioritize).
        </li>
      </ul>
      <Callout>
        Your reply is <strong>guidance, not authorization</strong>: it re-enters the planner as context and can
        never widen scope — the guard and flag gate still decide what a tool may do. If you don't reply within
        the timeout, the agent proceeds autonomously but <strong>never</strong> launches an intrusive tool
        without an explicit approval.
      </Callout>

      <SectionTitle>Tool catalog</SectionTitle>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr><th>Tool</th><th>Type</th><th>What it does</th></tr>
          </thead>
          <tbody>
            {TOOLS.map((t) => (
              <tr key={t.name}>
                <td className="mono">
                  {t.name}
                  {t.gated && <span className="badge sev-medium" style={{ marginLeft: 8 }}>gated</span>}
                </td>
                <td><span className="badge pill">{t.kind}</span></td>
                <td className="muted">{t.what}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <SectionTitle>Reading the graph</SectionTitle>
      <p className="muted">
        The knowledge graph is live. Node fill encodes the entity's role — structural nodes
        (engagements, hosts, ports) render hollow, pink fill with a thin white outline, while the notable
        "pop" layer (services, findings) renders solid white — and edges show relationships (a host{" "}
        <em>has</em> a port, a finding <em>affects</em> a host). Hover a node to highlight its
        connections. It's the same data the dashboard and report draw from, just visualized.
      </p>

      <SectionTitle>Troubleshooting</SectionTitle>
      <div className="stack" style={{ gap: 10 }}>
        <Callout>
          <div>
            <strong>A run is stuck or failed.</strong> Runs execute off the request thread inside a sandbox; a
            Docker or setup problem fails the run rather than the request. Check the API logs and that the
            sandbox runtime is available.
          </div>
        </Callout>
        <Callout>
          <div>
            <strong>Findings aren't appearing.</strong> Confirm the target is inside the engagement's scope,
            that the CVE database was seeded (<code className="k">python -m app.cve_seed</code>), and that
            Postgres and Neo4j are reachable.
          </div>
        </Callout>
        <Callout>
          <div>
            <strong>An intrusive tool is refused.</strong> Exploitation and credential attacks require the
            matching authorization flag on the engagement, plus their integration secrets (Metasploit RPC,
            etc.). See the API docs for the full configuration.
          </div>
        </Callout>
      </div>

      <div style={{ marginTop: 28 }}>
        <Callout>
          Full architecture, deployment, and configuration live in the project's <code className="k">README.md</code> and
          <code className="k"> IMPLEMENTATION_REPORT.md</code>. The interactive API reference is at{" "}
          <a href={`${API_BASE}/docs`} target="_blank" rel="noreferrer" style={{ color: "var(--brand)" }}>/docs</a>.
        </Callout>
      </div>
    </main>
  );
}
