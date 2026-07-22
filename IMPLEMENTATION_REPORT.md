# Pinkeye — Implementation Report

_AI-powered DAST/SAST vulnerability-assessment and red-team harness._

## 1. Goal

Pinkeye runs **authorized** vulnerability assessments (dynamic + static) and gated red-team
activity against targets the operator owns or is contracted to test, then represents everything it
finds as a **knowledge graph** with a dashboard, a queryable API, and a Markdown report.

The design bet is that the durable value is not "an LLM that runs nmap" — that is commodity — but a
**strong harness**: a deterministic control plane wrapped around a swappable model, so tool
execution, sandbox isolation, scope enforcement, scoring, and correlation stay reliable regardless of
which LLM is plugged in. The LLM plans and triages; the harness makes it safe, reproducible, and
auditable.

## 2. Architecture

```
   Web UI (Next.js/React/TS)  ── network map · dashboard (KPIs) · query · Cypher
            │ REST + polling
   Control plane (FastAPI)     ── auth/RBAC · scope guard · run orchestration · audit log
            │                     query API · KPIs · correlation · reporting
   ┌────────┼───────────────────────────┐
   │        │                           │
 Neo4j   Postgres                 Agent runtime (Python)
 (graph/  (system of record:      ── LLM planning loop (model-agnostic)
  map)     findings, runs,           tool registry · scope-guarded execution
           CVE DB, audit,         ── sandbox (Docker) + in-process "local" tools
           job queue, tenants)    ── normalizers → findings → enrich (CVSS/ATT&CK)
                                        │ MCP-style typed tool calls
                                   Sandbox: nmap · nuclei/zap/nikto/ffuf ·
                                   semgrep/gitleaks/trivy · hydra
                                   Local: cve_lookup · virustotal · tls_cert · metasploit
```

**Repositories**
- `control-plane/` — FastAPI service: scope guard, audit log, repositories, query/KPI/correlation/
  report logic, CVSS + ATT&CK, CVE database, RBAC, rate limiting, job queue, worker.
- `agent-runtime/` — LLM providers + planning loop, the tool registry, sandbox runner, all tools and
  output normalizers, egress policy, exploitation/credential modules.
- `web/` — Next.js UI (network map, dashboard, query).
- `deploy/` — docker-compose + Dockerfiles.
- `graph/` — Neo4j schema (constraints/indexes).

**Core data flow:** operator defines a target + signed scope → orchestrator creates a run →
planner/agent proposes a tool + target → **scope guard authorizes in code** → tool runs (sandbox or
in-process) → raw output is normalized to findings → findings are **enriched** with CVSS + ATT&CK →
written to Neo4j (graph) and Postgres (durable) → every step is appended to the audit log → the UI/API
read the graph, KPIs, attack chains, and report.

## 3. Design principles

1. **The harness owns execution; the model owns intent.** The model proposes a tool + target; the
   harness validates, executes, captures structured output, and feeds back a short summary. The model
   never gets a shell.
2. **Deny-by-default scope guard, in code, un-bypassable.** Every tool call is authorized against a
   **signed** engagement scope before anything runs. The signature covers the whole scope
   (allowlists, time window, intensity ceiling, and the offensive flags), so the model cannot widen
   its own blast radius — an out-of-scope or unauthorized action comes back as a denial it must work
   around.
3. **Model-agnostic.** One `LLMProvider` interface with Claude / OpenAI-compatible / Ollama adapters,
   selectable per role by environment variable.
4. **Everything is audited and replayable.** Each step logs the tool, target, scope decision, and a
   SHA-256 of the raw output; a run can be reconstructed and its integrity verified.
5. **Graceful degradation.** If Postgres/Neo4j are down the API still serves (in-memory fallback);
   with no API keys configured it runs in open dev mode.

## 4. What was built (by phase)

| Phase | Delivered |
|------|-----------|
| 1 | Single-host skeleton: scope guard, audit log, nmap recon end-to-end, Neo4j graph, web map |
| — | Persistence + query layer: Postgres system-of-record, migrations, repositories, filtered findings, entity search, read-only Cypher, KPI dashboard |
| 2 | Model-agnostic `LLMProvider` + the propose→validate→execute→observe agent loop with token/tool-call budgets |
| 3 | DAST: nuclei, nikto, ffuf (+ ZAP later) with normalizers; Endpoint graph nodes |
| 4 | SAST: semgrep, gitleaks, trivy; `allowed_artifacts` scope surface; read-only source mount |
| 5 | Correlation (attack chains), validation (corroboration + gated Metasploit), Markdown reporting |
| 6 | Hardening: per-job egress policy, gVisor toggle, secrets loading, run replay, dedup tuning |
| 7 | Multi-tenant: `tenant_id` everywhere, API-key RBAC, per-tenant rate limits, durable job queue + worker |

**Capability expansion (session 2)**
- Fixed the audit-sink thread-safety bug (pool-based writes) and bounded the graph query.
- **CVSS v3.1** base-score computation + **MITRE ATT&CK** technique mapping, applied on the write path.
- **Local CVE database** + an offline `cve_lookup` tool the agent uses to identify vulnerabilities.
- **VirusTotal** hash-reputation (malware presence) and **TLS certificate** inspection tools.
- **ZAP** DAST with **authenticated scanning** (header/token injection via a run auth profile).
- **Gated exploitation + post-exploitation** (Metasploit) and **gated credential attacks** (hydra).

## 5. Tool inventory (14)

| Tool | Category | Surface | Notes |
|------|----------|---------|-------|
| `nmap` | recon | network | port/service discovery |
| `nuclei` | DAST | network | templates/CVEs; captures CVSS vector |
| `nikto` | DAST | network | server misconfig |
| `ffuf` | DAST | network | content/endpoint discovery |
| `zap` | DAST | network | baseline/full scan; **authenticated** via auth profile |
| `semgrep` | SAST | artifact | code vulns (CWE-mapped) |
| `gitleaks` | SAST | artifact | committed secrets |
| `trivy` | SAST | artifact | dependency/container CVEs |
| `cve_lookup` | knowledge | knowledge | offline CVE DB lookup by product/version |
| `virustotal` | intel | knowledge | file-hash malware reputation |
| `tls_cert` | intel | network | cert expiry / self-signed inspection |
| `exploit` | exploitation | network | **gated** `allow_exploit`; check-only default |
| `post_exploit` | post-ex | network | **gated**; read-only enumeration allowlist only |
| `credential_attack` | creds | network | **gated** `allow_credential_attacks`; hard-capped hydra |

Surfaces determine authorization: **network** → CIDRs/domains; **artifact** → source paths; **knowledge**
→ no target (valid signed scope suffices). Tools with `local=True` run in-process instead of the sandbox.

## 6. Security & gating model

This is the most important section. The harness supports intrusive capabilities, all held behind
layered controls:

- **Signed-scope opt-in flags.** Exploitation and credential attacks require `allow_exploit` /
  `allow_credential_attacks` to be set in the engagement scope. These flags are part of the scope's
  canonical signed string, so they cannot be flipped on without re-signing — and the model has no
  signing key. `execute_tool_step` refuses any `requires_flag` tool whose flag is not granted.
- **Non-destructive defaults.** The exploit tool runs Metasploit's `check` unless the caller
  explicitly sets `action="exploit"` (and the flag is granted). Credential attacks are hard-capped
  (≤4 threads, inter-attempt wait, stop-on-first) — spraying for weak credentials, not brute force —
  to avoid account lockout and service DoS.
- **Post-exploitation is enumeration-only.** It operates only on a session already opened by the
  exploit tool and is restricted **in code** to a read-only allowlist (identity, OS, privileges,
  network). Persistence, C2, upload, and arbitrary command execution are deliberately not
  implemented and are refused.
- **Sandbox isolation.** Offensive tooling runs in disposable containers (no host mounts, dropped
  capabilities, read-only rootfs, CPU/mem/pid limits), with an optional stronger runtime
  (`EYE_SANDBOX_RUNTIME=runsc` for gVisor) and a per-job egress allow-list derived from the scope.
- **Secrets never in run input.** VirusTotal / Metasploit / auth credentials load from mounted secret
  files or environment (`app.secrets`), referenced by name in run config, and are not stored in
  findings or the audit trail.
- **Full audit + replay.** Every scope decision, tool start/finish (with output hash), and finding is
  appended to `audit_events`; `app.replay` reconstructs and integrity-checks a run.

**Deliberately excluded:** persistence/backdoors, C2 infrastructure, detection/AV evasion,
self-propagation, and any destructive payloads. Post-exploitation stops at evidencing impact.

## 7. Scoring, intelligence, and correlation

- **CVSS v3.1** (`app/cvss.py`): computes the real base score from a vector (verified: Log4Shell =
  10.0), falls back to a representative score per severity label; findings are sorted CVSS-first.
- **MITRE ATT&CK** (`app/attack.py`): maps CWE/category to a technique (id + name), surfaced on
  findings and in the report.
- **CVE database** (`app/cve_db.py`, migration `0005`, seed `app/data/cve_seed.json`): offline lookup
  the agent queries via `cve_lookup` to map a fingerprinted product/version to known CVEs; also a
  `/cve` API endpoint. Refresh from an NVD export via `python -m app.cve_seed <file.json>`.
- **Correlation** (`app/correlation.py`): builds attack chains — per-host severity escalation and
  **code-to-runtime linking by shared CWE** (a weakness in source that is also reachable at runtime).
- **Reporting** (`app/report.py`): a Markdown report generated straight from graph/DB facts, with
  KPIs, attack chains, and per-finding CVSS + ATT&CK.

## 8. Knowledge graph model (Neo4j)

Node types: `Engagement`, `IP`, `Port`, `Service`, `Endpoint`, `Finding`, `AttackChain`.
Key relationships: `IP-[:EXPOSES]->Port-[:RUNS]->Service`, `Finding-[:AFFECTS]->(IP|Endpoint)`,
`AttackChain-[:STEP]->Finding`. Every node carries `engagement_id` (and `tenant_id` in Phase 7). The
UI network map is a direct projection; attack chains are highlighted paths.

## 9. Testing

**67 automated tests pass** (31 control-plane + 36 agent-runtime), covering the deterministic core:
scope guard (incl. tampered-signature and out-of-scope rejection), all output normalizers, the agent
loop (incl. the model being unable to widen scope), CVSS math, ATT&CK mapping, CVE lookup, VirusTotal
+ TLS parsing, ZAP auth-command construction, exploitation gating + check-only default +
enumeration-only post-ex, credential-attack gating + thread caps, query builders + read-only Cypher
guard, replay integrity, RBAC, and rate limiting.

Also verified: the FastAPI app imports with all routes, a TestClient smoke test (engagement/run CRUD,
RBAC 401/403/200, offensive-flag signing), the web app type-checks and `next build` succeeds, and all
five migrations + the CVE seed package into the built wheel.

## 10. Known limitations / not yet verified

- **No live infrastructure in the build environment.** The pure logic is unit-tested, but live tool
  execution, Postgres/Neo4j round-trips, VirusTotal/Metasploit calls, and the end-to-end scan against
  a deliberately vulnerable target still need the real stack (see README verification steps).
- **UI gaps:** attack chains, report download, validation, and agent-run transcript are exposed by the
  API but not yet surfaced in the web UI; errors are currently swallowed client-side.
- **Docker socket mount** gives the API/worker full daemon access (single-host trade-off); a brokered
  rootless runner is the intended hardening.
- **Egress enforcement** is a computed policy + a pluggable enforcer seam; actual netfilter rules must
  be wired per deployment.
- **Coverage:** the system augments — it does not replace — dedicated scanners or manual pentesting;
  LLM triage can hallucinate or miss, so findings are assisted triage with a human in the loop.

## 11. Authorization notice

Pinkeye is for **authorized** security testing only — assets you own or have written permission
to test. The signed-scope requirement, the offensive-capability flags, sandboxing, rate limits, and
audit trail are the technical expression of that rule. Operators are responsible for ensuring every
engagement is properly authorized before enabling intrusive capabilities.
