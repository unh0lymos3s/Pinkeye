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

```bash
cd deploy
docker compose up --build
```

This starts five services:

| Service | URL / port | Purpose |
|---------|-----------|---------|
| `web` | http://localhost:3000 | UI: network map, dashboard, query |
| `api` | http://localhost:9000 (`/docs` for OpenAPI) | control plane |
| `worker` | — | drains the job queue (scale with `--scale worker=N`) |
| `neo4j` | http://localhost:7474 (bolt 7687) | knowledge graph |
| `postgres` | 5432 | durable store |

The API auto-runs database migrations and applies the Neo4j schema on startup. **Then seed the CVE
database** so `cve_lookup` and `/cve` work:

```bash
docker compose exec api python -m app.cve_seed
```

Open http://localhost:3000, create an engagement scoped to a lab network, and launch a scan.

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
| `EYE_LLM_PROVIDER` | `claude` | `claude` \| `openai` \| `ollama` |
| `EYE_LLM_MODEL` | provider default | model id; `EYE_LLM_<ROLE>_MODEL` overrides per role |
| `EYE_LLM_BASE_URL` | — | base URL for the OpenAI-compatible adapter (vLLM/LM Studio/etc.) |
| `EYE_SANDBOX_RUNTIME` | daemon default (`runc`) | e.g. `runsc` for gVisor isolation |
| `EYE_EGRESS_ENFORCER` | — | external command applying per-job egress firewall rules |
| `EYE_SECRETS_DIR` | `/run/secrets` | directory scanned for secret files |

Secrets (via `EYE_SECRETS_DIR` files or env): `VT_API_KEY` (VirusTotal), `MSF_RPC_PASSWORD`,
`MSF_RPC_HOST`, `MSF_RPC_PORT` (Metasploit RPC).

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

### Key API endpoints

| Method / path | Purpose |
|---------------|---------|
| `POST /engagements`, `GET /engagements`, `GET /engagements/{id}` | manage engagements |
| `POST /engagements/{id}/runs`, `GET /runs/{id}` | launch / inspect runs |
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
