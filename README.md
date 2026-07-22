# Pinkeye

Read the description, its a wrapper I just designed it Claude wrote the code. AI slop begins down below:

> ⚠️ **Authorized use only.** Only run against assets you own or are contracted to test. Every run is
> bound to a **signed scope** the harness enforces in code before any tool executes. Intrusive
> capabilities (exploitation, credential attacks) are off unless explicitly authorized in that scope.

See [`IMPLEMENTATION_REPORT.md`](IMPLEMENTATION_REPORT.md) for the full architecture and design.

## Layout

| Path | What |
|------|------|
| `control-plane/` | FastAPI service: scope guard, audit log, repositories, query/KPI/correlation/report, RBAC, job queue, worker |
| `agent-runtime/` | LLM providers + planning loop, tool registry, sandbox runner, tools + normalizers |
| `web/` | Next.js UI: network map, dashboard, query |
| `deploy/` | docker-compose + Dockerfiles |
| `graph/` | Neo4j schema (constraints/indexes) |

## Prerequisites

- **Docker + Docker Compose** (the quickest path — brings up the whole stack).
- For local (non-Docker) development: **Python 3.11+**, **Node 20+**, and reachable **Postgres 16** and
  **Neo4j 5** instances.

---

## Quick start (Docker Compose)

The app stack runs in containers and the agent talks to **Ollama Cloud** directly
(`https://ollama.com/v1`) — no host Ollama, no GPU. Put your Ollama API key (from
https://ollama.com/settings/keys) in `deploy/.env`, then bring up the stack:

```bash
echo 'OLLAMA_API_KEY=<your-key>' > deploy/.env    # gitignored; compose loads it automatically
cd deploy
docker compose up --build
```

Compose reads `deploy/.env` and injects the key into `api`/`worker` (which are pre-wired to
`EYE_LLM_PROVIDER=openai`, `EYE_LLM_BASE_URL=https://ollama.com/v1`,
`EYE_LLM_MODEL=minimax-m3:cloud`). This starts five services:

| Service | URL / port | Purpose |
|---------|-----------|---------|
| `web` | http://localhost:3000 | UI: network map, dashboard, query, `/agent` chat |
| `api` | http://localhost:9000 (`/docs` for OpenAPI) | control plane |
| `worker` | — | drains the job queue (scale with `--scale worker=N`) |
| `neo4j` | http://localhost:7474 (bolt 7687) | knowledge graph |
| `postgres` | 5432 | durable store |

The API auto-runs database migrations and applies the Neo4j schema on startup. **Then seed the CVE
database** so `cve_lookup` and `/cve` work:

```bash
docker compose exec api python -m app.cve_seed
```

Open http://localhost:3000, create an engagement scoped to a lab network, and launch a scan (or use
the `/agent` chat for an LLM-planned run). Any Ollama Cloud model works — set `EYE_LLM_MODEL` on the
`api`+`worker` services (e.g. `gemma4:31b`, `gpt-oss:120b`). To run **fully on-host with no cloud**
instead, point at a host/containerized Ollama (`EYE_LLM_PROVIDER=ollama`, `EYE_LLM_BASE_URL` at it)
with a locally pulled model like `llama3.1` — see "Connecting an LLM provider".

> The compose file ships with insecure dev defaults (passwords, `EYE_SCOPE_SIGNING_KEY`). **Change
> them for anything beyond a local lab** — the scope guard's signatures depend on the signing key.

---

## Build & deploy

### Build the images

```bash
# from repo root
docker compose -f deploy/docker-compose.yml build          # all images
docker build -f deploy/api.Dockerfile -t eye-api .          # API + worker (same image)
docker build -f deploy/web.Dockerfile -t eye-web ./web      # UI
```

The API image bundles both Python packages (`control-plane` + `agent-runtime`) so the API can run the
orchestrator in-process and the worker can run the same code path.

### Deploy checklist (beyond a local lab)

1. **Set real secrets/config** (see the table below): a strong `EYE_SCOPE_SIGNING_KEY`, DB
   credentials, and `EYE_API_KEYS` to turn on authentication (otherwise the API is open dev-mode
   admin).
2. **Run migrations** (idempotent; also run automatically on API start):
   ```bash
   docker compose exec api python -m app.db.migrate
   ```
3. **Seed / refresh the CVE database** (bundled starter set, or an NVD JSON export):
   ```bash
   docker compose exec api python -m app.cve_seed            # bundled set
   docker compose exec api python -m app.cve_seed /path/nvd.json
   ```
4. **Mount secrets** for optional integrations (see "Enabling optional integrations").
5. **Scale workers** for throughput: `docker compose up -d --scale worker=4`.
6. **Harden the sandbox** for real targets: set `EYE_SANDBOX_RUNTIME=runsc` (gVisor) and wire
   `EYE_EGRESS_ENFORCER`. Note the Docker-socket mount grants daemon access — replace with a brokered
   runner for shared hosts.

### Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `EYE_NEO4J_URI` | `bolt://localhost:7687` | Neo4j bolt endpoint |
| `EYE_NEO4J_USER` / `EYE_NEO4J_PASSWORD` | `neo4j` / `eye-dev-password` | Neo4j auth |
| `EYE_POSTGRES_DSN` | `postgresql://eye:eye@localhost:5432/eye` | Postgres DSN |
| `EYE_SCOPE_SIGNING_KEY` | `dev-insecure-signing-key` | **HMAC key for signing scopes — set this** |
| `EYE_API_KEYS` | _(unset → open dev mode)_ | RBAC keys: `key:tenant:role,...` (role = viewer\|operator\|admin) |
| `EYE_LLM_PROVIDER` | `ollama` | `claude` \| `openai` \| `ollama` (default targets a local Ollama at `localhost:11434`) |
| `EYE_LLM_MODEL` | provider default | model id; `EYE_LLM_<ROLE>_MODEL` overrides per role |
| `EYE_LLM_BASE_URL` | — | base URL for the `openai`/`ollama` adapter (Ollama, vLLM/LM Studio, or a LiteLLM proxy) |
| `EYE_LLM_API_KEY` | — | API key for the `openai` adapter; falls back to `OPENAI_API_KEY`. Claude reads `ANTHROPIC_API_KEY`; Ollama needs none |
| `EYE_LLM_CONFIG` | — | path to a JSON router file, re-read each run — edit to hot-swap the model/fallbacks with no restart |
| `EYE_LLM_FALLBACK_MODELS` | — | comma list of `provider:model` (or bare `model`) tried in order when the primary refuses |
| `EYE_UPLOAD_ROOT` | `/eye-uploads` | where SAST uploads are extracted; must be the same absolute path on host + api/worker + any MCP SAST sibling |
| `EYE_SANDBOX_RUNTIME` | daemon default (`runc`) | e.g. `runsc` for gVisor isolation |
| `EYE_EGRESS_ENFORCER` | — | external command applying per-job egress firewall rules |
| `EYE_SECRETS_DIR` | `/run/secrets` | directory scanned for secret files |
| `EYE_MCP_SERVERS` | — | inline JSON mapping a tool to an MCP server backend (see below) |
| `EYE_MCP_CONFIG` | — | path to a JSON file with the same shape as `EYE_MCP_SERVERS` |

Secrets (via `EYE_SECRETS_DIR` files or env): `VT_API_KEY` (VirusTotal), `MSF_RPC_PASSWORD`,
`MSF_RPC_HOST`, `MSF_RPC_PORT` (Metasploit RPC).

### MCP tool backends (optional)

A registered tool can execute via an external **MCP server** (semgrep, trivy, nmap, ZAP, nuclei,
VirusTotal, Metasploit, …) instead of the local sandbox. It is opt-in per tool: with no config every
tool runs in the sandbox as before. Crucially, the harness only ever acts as an MCP **client**, and
an MCP-backed tool is *wrapped* so the **scope guard, offensive-flag gate, and audit still run first**
— the model never gets raw MCP access and an out-of-scope target never reaches the server.

```bash
# Run the SAST slot via Snyk Code — pooled in its own hardened container (verified live) — trivy via
# its plugin, nmap via a community one. Snyk needs SNYK_TOKEN (free-tier works); it's forwarded by
# name into the sibling. Build the Snyk MCP image first: `docker compose build mcp-snyk`.
export SNYK_TOKEN=<your-token>
export EYE_MCP_SERVERS='{
  "semgrep": {"pooled": true, "image": "eye-mcp-snyk:latest", "tool": "snyk_code_scan", "target_arg": "path", "env": {"SNYK_TOKEN": "'"$SNYK_TOKEN"'"}, "mounts": ["'"$PWD"'/deploy/samples:/samples:ro"]},
  "trivy":   {"command": "trivy", "args": ["mcp", "-t", "stdio"], "tool": "scan_filesystem", "target_arg": "path"},
  "nmap":    {"command": "npx", "args": ["-y", "nmap-mcp-server"], "tool": "run_nmap_scan", "target_arg": "target"}
}'
```

`pooled: true` runs the server in a **warm, locked-down container** (`docker run --rm -i`, cap-drop-all
/ read-only / no-new-privileges, no Docker socket) that a process-wide pool reuses across calls and
evicts after `EYE_MCP_IDLE_TTL` (default 300s) idle — lighter than spawn-per-call **and** isolated from
the api process. Use it for read-only analyzers; keep offensive/network tools in the disposable
per-run sandboxes. The simpler spawn-per-call form (`command`/`args`, no `pooled`) is shown for
`trivy`/`nmap`. The default `target_mode: "value"` passes the scope-checked target through as a plain
string (a source path for `snyk_code_scan`, a host for nmap, a URL for ZAP); `target_mode: "path_list"`
is also available. See [`list.md`](list.md#mcp-integration) for the availability table and full spec fields.

### Connecting an LLM provider

The model layer is model-agnostic (`agent-runtime/runtime/llm/`): three env vars pick the
provider, model, and (where needed) endpoint/key. Set them on whatever process runs the agent
— the `uvicorn` API and the `worker` for local dev, or the `api` and `worker` services in
Compose (**both** — either can launch an agent run). Selection happens fresh per run, so a
changed env/config takes effect on the next run.

**Ollama Cloud — the default.** Compose points `api`/`worker` at Ollama's cloud over the OpenAI-
compatible endpoint, so there's no host Ollama and no GPU. Provide an API key from
https://ollama.com/settings/keys (in `deploy/.env` as `OLLAMA_API_KEY`, or exported):

```bash
export EYE_LLM_PROVIDER=openai
export EYE_LLM_MODEL=minimax-m3:cloud   # any cloud model: gemma4:31b, gpt-oss:120b, deepseek-v3.1:671b, …
export EYE_LLM_BASE_URL=https://ollama.com/v1
export EYE_LLM_API_KEY=...               # your Ollama key (compose reads OLLAMA_API_KEY from deploy/.env)
```

**Local / self-hosted Ollama (fully on-host, no cloud) — the built-in default.** With no
`EYE_LLM_*` set, the harness uses a local Ollama at `http://localhost:11434/v1` (model
`minimax-m3:cloud`), so a bare local run needs no LLM env at all. Run Ollama yourself and point at it;
from a container use `http://host.docker.internal:11434/v1` (needs the host reachable from Docker —
bind Ollama to `0.0.0.0` and allow the Docker subnet through any host firewall), or run Ollama as a
compose service on the same network:

```bash
ollama serve &
ollama pull llama3.1
# The provider/base_url already default to local Ollama; set these only to override the model/endpoint.
export EYE_LLM_PROVIDER=ollama EYE_LLM_MODEL=llama3.1 EYE_LLM_BASE_URL=http://localhost:11434/v1
```

**Any OpenAI-compatible API** — OpenAI, Groq, Together, OpenRouter, vLLM, LM Studio, or a
**LiteLLM proxy** — just point `base_url` at it and supply a key:

```bash
export EYE_LLM_PROVIDER=openai
export EYE_LLM_MODEL=gpt-4o                          # whatever id the endpoint serves
export EYE_LLM_BASE_URL=https://api.groq.com/openai/v1   # omit for OpenAI itself
export EYE_LLM_API_KEY=sk-...                        # or set OPENAI_API_KEY
```

**Anthropic Claude:**

```bash
export EYE_LLM_PROVIDER=claude
export EYE_LLM_MODEL=claude-fable-5
export ANTHROPIC_API_KEY=sk-ant-...
```

Verify the runtime can see a provider before launching a run:

```bash
python -c "from runtime.llm.config import get_provider; print(type(get_provider()).__name__)"
```

**Hot-swap (no restart).** `get_provider()` runs fresh at the start of every run, so
a `EYE_LLM_CONFIG` JSON file is re-read each time — edit it and the next run picks up
the change. A LiteLLM *proxy* also works as the `EYE_LLM_BASE_URL` target via the
OpenAI-compatible adapter (no in-process dependency).

```json
{ "provider": "openai", "model": "minimax-m3:cloud",
  "base_url": "https://ollama.com/v1",
  "fallbacks": ["openai:gpt-oss:120b", "claude:claude-fable-5"] }
```

**Refusals.** Safety-tuned local models sometimes decline an authorized recon step,
returning apologetic text and no tool call — which otherwise looks identical to
"finished," silently ending the run. When any `fallbacks` are configured the provider
is wrapped so that on a detected refusal it (1) re-asserts the engagement's signed
authorization and retries the same model once, then (2) walks the fallback chain until
a model cooperates, emitting a `refusal` event to the transcript at each transition.

**Model selection.** Heavily RLHF'd chat models often over-refuse security phrasing;
for authorized engagements prefer security-amenable local models and put a stronger
hosted model last in the fallback chain as a backstop.

> **Boundary.** The only real safety control is the HMAC-signed scope guard, enforced
> in code before any tool runs — every proposed action is validated against the signed
> scope regardless of what the model agrees to. Refusal handling is a *reliability*
> measure for in-scope, authorized work (re-stating authorization the engagement
> already carries); it is not a jailbreak and cannot widen scope. Out-of-scope or
> genuinely harmful actions are denied by the guard no matter which model is plugged in.

---

## Local development (without Docker)

```bash
# Control plane + agent runtime (editable installs into one venv)
python -m venv .venv && source .venv/bin/activate
pip install -e './control-plane[dev]' -e './agent-runtime[dev]'

# Point at running Postgres/Neo4j, then migrate + seed
export EYE_POSTGRES_DSN=postgresql://eye:eye@localhost:5432/eye
python -m app.db.migrate
python -m app.cve_seed

# Run the API and (separately) a worker
uvicorn app.main:app --reload --port 9000
python -m app.worker

# Web UI
cd web && npm install && npm run dev     # http://localhost:3000
```

### Run the tests

```bash
cd control-plane && pytest        # 31 tests: scope guard, query, scoring, correlation, tenancy, hardening
cd agent-runtime && pytest        # 36 tests: normalizers, agent loop, tools, exploitation/creds gating
cd web && npm run build           # type-check + production build
```

---

## Usage

### Create an engagement (defines the signed scope)

```bash
curl -X POST localhost:9000/engagements -H 'content-type: application/json' -d '{
  "name": "lab",
  "allowed_cidrs": ["10.0.0.0/24"],
  "allowed_domains": ["lab.example.com"],
  "allowed_artifacts": ["/repos/app"],
  "max_intensity": "normal"
}'
```

Add `"allow_exploit": true` and/or `"allow_credential_attacks": true` **only** for engagements where
those are authorized — they are baked into the scope signature.

### Launch a run

```bash
# deterministic single tool
curl -X POST localhost:9000/engagements/<id>/runs -H 'content-type: application/json' \
  -d '{"target":"10.0.0.5","tool":"nmap","intensity":"light"}'

# LLM agent plans multi-step recon/scan across all authorized tools
curl -X POST localhost:9000/engagements/<id>/runs -H 'content-type: application/json' \
  -d '{"target":"10.0.0.5","mode":"agent"}'

# authenticated DAST with ZAP (credential resolved from a secret named "app-token")
curl -X POST localhost:9000/engagements/<id>/runs -H 'content-type: application/json' \
  -d '{"target":"https://lab.example.com","tool":"zap",
       "auth":{"header_name":"Authorization","value_ref":"app-token"}}'
```

With `EYE_API_KEYS` set, pass `-H "X-API-Key: <key>"`; writing requires `operator`, reading `viewer`.

### SAST: scan an uploaded codebase

The **SAST** tab (`/sast`) lets an operator upload a codebase — a `.zip` / `.tar` / `.tar.gz`, or a
single source file — instead of pre-mounting a repo path. The harness extracts it, **authorizes the
extracted directory by adding it to the engagement's signed scope** (`allowed_artifacts`, re-signed),
then runs the `sast` specialist over it with the chosen analyzers streaming live: **Snyk Code** (the
`semgrep` slot when the Snyk MCP backend is wired, else Semgrep), **gitleaks** (secrets), and
**trivy** (dependency CVEs). Uploading is the authorization decision — it is operator-gated, audited,
and can only ever add a local source path; it never grants a network or offensive capability.

```bash
# Raw file as the request body; the server extracts it and returns the path a SAST run targets.
curl -X POST "localhost:9000/engagements/<id>/sast/upload?filename=app.zip" \
  --data-binary @app.zip -H 'content-type: application/octet-stream'
# -> {"path":"/eye-uploads/<id>/<uuid>","file_count":123,"kind":"zip", ...}

# Then scan it (agent `sast` profile over the enabled analyzers):
curl -X POST localhost:9000/engagements/<id>/runs -H 'content-type: application/json' \
  -d '{"target":"/eye-uploads/<id>/<uuid>","mode":"agent","profile":"sast",
       "enabled_tools":["semgrep","gitleaks","trivy"]}'
```

> **Shared upload path (important for Docker/MCP).** The extracted path must resolve to the **same
> absolute path** for the api container, the disposable sandbox (bind-mounted at `/src`), and any MCP
> SAST sibling (e.g. the pooled Snyk container). The Compose file wires this: `EYE_UPLOAD_ROOT`
> (`/eye-uploads`) is a host bind mount at an identical `host:container` path on `api`/`worker`, and is
> mounted read-only into the Snyk sibling. Running locally (no containers) it is just a host directory,
> so paths already match. Set `EYE_UPLOAD_ROOT` to relocate it.

### Run an engagement with the LLM agent (end-to-end)

Agent mode (`"mode":"agent"`) hands planning to the configured LLM: it proposes tool calls,
the harness validates each against the signed scope, executes it in a sandbox, and feeds back a
short summary. Steps:

```bash
# 1. Put your Ollama key in deploy/.env and bring up the stack — the provider is already wired
#    (Ollama Cloud direct). Skip to step 3 once it's running.
echo 'OLLAMA_API_KEY=<your-key>' > deploy/.env
docker compose -f deploy/docker-compose.yml up --build -d
# --- OR run the agent locally instead of in Compose (see "Connecting an LLM provider"): ---
# export EYE_LLM_PROVIDER=openai EYE_LLM_MODEL=minimax-m3:cloud EYE_LLM_BASE_URL=https://ollama.com/v1 EYE_LLM_API_KEY=...
# export EYE_LLM_FALLBACK_MODELS="claude:claude-fable-5"   # optional backstop, needs ANTHROPIC_API_KEY
# uvicorn app.main:app --port 9000 &
# python -m app.worker &

# 3. Create an engagement (defines the signed scope the agent can never exceed):
EID=$(curl -s -X POST localhost:9000/engagements -H 'content-type: application/json' \
  -d '{"name":"lab","allowed_cidrs":["10.0.0.0/24"],"max_intensity":"normal"}' | jq -r .id)

# 4. Launch an agent run. `objective` is free-text guidance (never authorization):
RID=$(curl -s -X POST localhost:9000/engagements/$EID/runs -H 'content-type: application/json' \
  -d '{"target":"10.0.0.5","mode":"agent","objective":"map exposed services and known CVEs"}' | jq -r .id)

# 5. Watch it think and act live (SSE), or replay the full transcript:
curl -N localhost:9000/runs/$RID/events        # streaming: plan, thinking, tool_call, finding, refusal…
curl -s localhost:9000/runs/$RID/transcript     # full JSON transcript
```

Or use the web UI: open **`/agent`** (http://localhost:3000/agent), pick the engagement, type the
objective, and watch the same event stream — tool calls, findings, and any `refusal`/fallback
transitions render inline. A model that declines an authorized step surfaces as a `refusal` event
(and `stop_reason: "model refused"`) rather than a silent finish.

### Key API endpoints

| Method / path | Purpose |
|---------------|---------|
| `POST /engagements`, `GET /engagements`, `GET /engagements/{id}` | manage engagements |
| `POST /engagements/{id}/runs`, `GET /runs/{id}` | launch / inspect runs |
| `POST /engagements/{id}/sast/upload?filename=` | upload a codebase (zip/tar/file) for static analysis; extracts + authorizes the path |
| `GET /runs/{id}/events` (SSE), `GET /runs/{id}/transcript` | live agent event stream / full transcript |
| `GET /map`, `GET /engagements/{id}/graph` | network map (capped) |
| `POST /engagements/{id}/graph/query` | read-only Cypher over the graph |
| `GET /engagements/{id}/findings` | filtered findings (severity/category/cve/state/text) |
| `GET /engagements/{id}/entities` | host/service entity search |
| `GET /engagements/{id}/metrics` | dashboard KPIs |
| `GET /engagements/{id}/chains` | correlated attack chains |
| `POST /engagements/{id}/validate` | promote corroborated findings to confirmed |
| `GET /engagements/{id}/report` | Markdown report (CVSS + ATT&CK) |
| `GET /cve?product=&version=` | offline CVE lookup |

## Enabling optional integrations

- **VirusTotal (`virustotal` tool):** provide `VT_API_KEY` as a secret/env var.
- **Exploitation / post-exploitation (`exploit`, `post_exploit`):** run `msfrpcd` and set
  `MSF_RPC_PASSWORD` (+ `MSF_RPC_HOST`/`MSF_RPC_PORT`); set `"allow_exploit": true` on the engagement.
  Exploitation defaults to a non-destructive `check`.
- **Credential attacks (`credential_attack`):** set `"allow_credential_attacks": true`; hydra runs
  hard-capped (≤4 threads, stop-on-first) to avoid lockout/DoS.

## Verifying end-to-end (recommended smoke test)

Stand up a **deliberately vulnerable target inside the sandbox network** (OWASP Juice Shop for web,
Metasploitable/DVWA for network) and run against **it only**:

1. Confirm the scope guard: a scan against an out-of-scope IP is hard-rejected and logged.
2. Run nmap, then an agent run; confirm hosts/ports/findings appear as connected nodes in the graph
   and in the dashboard KPIs.
3. Confirm known-planted vulns show up as normalized, deduped findings with CVSS + ATT&CK mapping.
4. Generate the report (`GET /engagements/{id}/report`) and re-run to confirm dedup (`times_seen`) and
   replay integrity.
