# Integrated Tools & Services

An inventory of every external tool, model provider, and backing service wired into **Pinkeye**.

> Note: The LLM plans over a fixed in-harness tool registry (`agent-runtime/runtime/registry.py`),
> and every tool is offered to the model with the same `{target, intensity}` shape. The model picks
> *what/where*; the harness owns *how* (command construction, sandboxing, scope enforcement).
>
> **MCP support (opt-in):** a tool can be executed via an external **MCP server** instead of the
> local sandbox — see [MCP integration](#mcp-integration) below. The model still only ever sees the
> `{target, intensity}` registry; MCP-backed tools run *behind* the scope guard, flag gate, and audit,
> so the safety spine is unchanged.

---

## Agent tools (the 14 registered scanners)

Each runs in a sandboxed container (or in-process for `knowledge`/`local` tools) and is gated by the
signed engagement scope. Offensive tools are registered always but refuse without their scope flag.

| # | Tool | Underlying binary/service | Surface | Purpose | Gate |
|---|------|---------------------------|---------|---------|------|
| 1 | `nmap` | Nmap | network | TCP port & service discovery (recon) | — |
| 2 | `nuclei` | Nuclei | network | Template-based web vuln scan (CVEs, misconfigs); target is a URL | — |
| 3 | `ffuf` | ffuf | network | Directory/endpoint discovery by fuzzing a base URL | — |
| 4 | `nikto` | Nikto | network | Web-server misconfig & known-issue scanner | — |
| 5 | `zap` | OWASP ZAP (`zaproxy/zap-stable`) | network | Dynamic web scan; supports **authenticated scanning** via header/token from the run's auth profile | — |
| 6 | `semgrep` | Semgrep | artifact | Static code analysis (SAST) over a source path | — |
| 7 | `gitleaks` | Gitleaks | artifact | Detects hardcoded secrets in source | — |
| 8 | `trivy` | Trivy | artifact | Scans dependencies & containers for known CVEs | — |
| 9 | `cve_lookup` | Local CVE DB (Postgres) | knowledge | Look up known CVEs for a product/version after fingerprinting | — |
| 10 | `virustotal` | VirusTotal API | knowledge | Check a file hash (md5/sha1/sha256) against VT for known-malware detections | `VT_API_KEY` |
| 11 | `tls_cert` | Python `ssl` (direct) | knowledge | Fetch & inspect a host's TLS cert (expiry, issuer, self-signed) | — |
| 12 | `exploit` | Metasploit (RPC) | network | Run a Metasploit module; **check-only by default**, firing needs `action='exploit'` | `allow_exploit` |
| 13 | `post_exploit` | Metasploit (RPC) | network | Read-only enumeration over an open session; **no persistence/C2** | `allow_exploit` |
| 14 | `credential_attack` | hydra (`vanhauser/hydra`) | network | Weak-credential testing — **spray, not brute force** (thread cap ≤4, `-f`); password never stored | `allow_credential_attacks` |

---

## MCP integration

The harness can run a tool through an external **MCP server** (Model Context Protocol) as an
alternative execution backend, keeping the same LLM-facing `{target, intensity}` contract. It is
**opt-in per tool**: with no config, every tool stays on its sandbox path unchanged.

**Safety model (unchanged spine):** an MCP-capable tool is *wrapped* by `MCPBackedTool`
(`agent-runtime/runtime/mcp/backend.py`), which mirrors its `name`/`surface`/`requires_flag`. So in
`execute_tool_step` the **scope guard, the offensive-flag gate, and the audit log all run first** —
only an already-authorized target is forwarded to the MCP server. The model never gets raw MCP tool
access and cannot widen scope. The harness acts purely as an MCP **client** (stdio JSON-RPC 2.0,
`runtime/mcp/client.py`); it never lets a server call back into the model.

### MCP availability per tool (researched July 2026)

| Tool | MCP server available? | Notable upstream(s) |
|------|----------------------|---------------------|
| `nmap` | ✅ community | PhialsBasement/nmap-mcp-server, cyproxio/mcp-for-security |
| `nuclei` | ✅ community | addcontent/nuclei-mcp, intelligent-ears/pd-tools-mcp |
| `ffuf` | ✅ community | cyproxio/mcp-for-security (FFUF) |
| `nikto` | ✅ community | FuzzingLabs/mcp-security-hub, chfle/Pentest-MCP-Server |
| `zap` | ✅ **official** | zaproxy ZAP MCP server; community dtkmn/mcp-zap-server |
| `semgrep` | ✅ **official** | **Snyk Code** (`snyk mcp` → `snyk_code_scan`) — current SAST MCP backend; also semgrep (`semgrep mcp`) |
| `trivy` | ✅ **official** | aquasecurity/trivy-mcp (`trivy mcp`) |
| `gitleaks` | ⚠️ via suites | bundled in FuzzingLabs / pentest-ai tool suites |
| `virustotal` | ✅ community | BurtTheCoder/mcp-virustotal, alephnan/MCP-VirusTotal |
| `exploit` / `post_exploit` | ✅ **official** | Rapid7 `msfmcpd`; community GH05TCREW/MetasploitMCP |
| `credential_attack` | ⚠️ via suites | broad pentest suites (0xSteph/pentest-ai) |
| `cve_lookup`, `tls_cert` | — n/a | our own local implementations; no external tool to wrap |

`runtime/mcp/config.py::MCP_CAPABLE` mirrors this table in code (reference only, not authorization).

### Configuring it

Two env knobs (re-read at startup, like the LLM config); inline overrides the file:

| Var | Meaning |
|-----|---------|
| `EYE_MCP_SERVERS` | inline JSON — `{tool_name: {command, args, tool, target_arg, ...}, ...}` |
| `EYE_MCP_CONFIG` | path to a JSON file with the same shape |

Example — run the SAST slot via **Snyk Code**, `trivy` via its official server, and `nmap` via a
community one (the `semgrep` key names the native tool slot; Snyk Code is the MCP server behind it):

```json
{
  "semgrep": {"pooled": true, "image": "eye-mcp-snyk:latest", "tool": "snyk_code_scan", "target_arg": "path",
              "env": {"SNYK_TOKEN": "..."}, "mounts": ["/host/src:/samples:ro"]},
  "trivy":   {"command": "trivy", "args": ["mcp", "-t", "stdio"], "tool": "scan_filesystem", "target_arg": "path"},
  "nmap":    {"command": "npx", "args": ["-y", "nmap-mcp-server"], "tool": "run_nmap_scan", "target_arg": "target"}
}
```

**Pooled, isolated hosting (`pooled: true`):** instead of spawning the server per call inside the api
process, the harness keeps a **warm session** to the server running in its **own hardened container**
(`image`, launched `docker run --rm -i` with cap-drop-all / read-only / no-new-privileges / pids-limit,
no Docker socket; secrets forwarded by name). A process-wide pool reuses the session across calls and
evicts it after `EYE_MCP_IDLE_TTL` idle. This is the resource-light **and** isolation-preserving option
— use it for read-only analyzers (SAST/deps/secrets) whose egress is a static vendor endpoint. The
`trivy`/`nmap` entries above show the simpler spawn-per-call form (no `pooled`).

Per-tool spec fields: `command`/`args`/`env` (launch the stdio server), `tool` (MCP tool to call),
`target_arg` (argument that receives the scope-checked target, default `target`), `target_mode`
(`value` — pass the target as-is, default; or `path_list` — shape a source path into a
`[{"path": …}]` list, expanding a directory to its files, as semgrep's `semgrep_scan` expects),
optional `intensity_arg`, and `extra_args` (static arguments merged into every call).

> **Verified live (2026-07-14):** tested against the **official `snyk mcp` server** (`snyk_code_scan`).
> Proven over the wire: the full MCP handshake, `tools/list`, `tools/call` dispatch, our scope guard
> authorizing an in-scope target and denying an out-of-scope one *before* the server is contacted, and
> our argument shaping matching Snyk's real `path` schema. **Findings were returned over the wire and
> mapped end-to-end** through the full `execute_tool_step` spine (scope guard → audit → MCP dispatch →
> mapping): a Flask command-injection sample produced a `high` / **CWE-78** "Command Injection" finding
> with the correct `filePath` and evidence, audited as `mcp[snyk:snyk_code_scan]`. The scan needs
> Snyk Code enabled on the org plus a `SNYK_TOKEN` (or a prior `snyk auth`); we pass `--disable-trust`
> so the server never blocks on the interactive folder-trust prompt. Repeatable, auto-skipping live
> test: `tests/test_mcp_live_snyk.py`.

---

## LLM providers (swappable)

The harness is model-agnostic behind an `LLMProvider` protocol; the deterministic harness holds the
safety, the model is pluggable. Selected via `EYE_LLM_*` env or a JSON config, with fallback chains.

| Provider | Adapter | Default model | Endpoint | Notes |
|----------|---------|---------------|----------|-------|
| **Anthropic Claude** | `llm/claude.py` | — | api.anthropic.com | Native Claude adapter; per-call `EYE_LLM_MAX_TOKENS` (default 8192) |
| **OpenAI-compatible** | `llm/openai_compat.py` | `gpt-4o` | configurable `base_url` | Works with OpenAI, vLLM, LM Studio, LiteLLM, etc. |
| **Ollama** | `llm/ollama.py` | `gemma4:cloud` | `http://localhost:11434/v1` | Subclass of OpenAI-compat; project default; local or Ollama Cloud |
| **Fake** | `llm/fake.py` | — | — | Deterministic test double (used in the test suite) |

A `RefusalAwareProvider` (`llm/refusal.py`) wraps any provider to detect/handle model refusals.

---

## Backing services & data feeds

Infrastructure and external data the harness depends on at runtime.

| Service | Role | Where |
|---------|------|-------|
| **PostgreSQL 16** | Durable system-of-record: findings, runs, audit log, jobs, CVE DB, run events | `control-plane/app/db/`, compose `postgres` |
| **Neo4j 5** | Knowledge graph / network map (hosts, ports, services, endpoints, attack chains) | `graph/schema.cypher`, compose `neo4j` |
| **Metasploit RPC** (`msfrpcd`) | Backing daemon for the `exploit` / `post_exploit` tools | `runtime/msf.py` |
| **VirusTotal API** | Hash reputation lookups for the `virustotal` tool | `runtime/tools/reputation.py` |
| **NVD / CVE data** | Seeds the local CVE DB (`app.cve_seed`; bundled set or NVD JSON export) | `control-plane` |
| **Docker Engine** | Sandbox runtime for network/artifact tools (host Docker socket in Phase 1; gVisor toggle) | `deploy/` |

---

## Stack components (not "tools", for completeness)

| Component | Tech | Purpose |
|-----------|------|---------|
| `control-plane` | FastAPI (Python 3.11+) | Scope guard, audit, repositories, query/KPI/correlation/report, RBAC, job queue, worker |
| `agent-runtime` | Python | LLM providers, planning loop, tool registry, sandbox runner, normalizers |
| `web` | Next.js 14 / React | UI: network map, dashboard, query, `/agent` chat (SSE) |
| `deploy` | Docker Compose | Orchestrates `web`, `api`, `worker`, `neo4j`, `postgres` |
