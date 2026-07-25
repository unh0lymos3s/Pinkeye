"""FastAPI control plane.

Exposes engagement/scope creation, run triggering, the network-map graph, the queryable findings
API, entity search, read-only Cypher, and the dashboard KPIs. Postgres is the durable store; if it
is unreachable the API falls back to an in-memory cache so the single-host dev stack still runs.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from .audit import AuditEvent, EventType, MemoryAuditSink, PostgresAuditSink
from .auth import Authenticator, Principal, has_role
from .config import assert_secure_authentication, is_development, settings
from .events import RunEventStore, RunInbox
from .memory import NetworkMemory
from .correlation import correlate
from .db.database import Database
from .graph import GraphClient
from .models import Engagement, Intensity, Run, RunStatus, Scope
from .query import FindingFilters, is_read_only_cypher
from .ratelimit import RateLimiter
from .report import generate_report
from .repositories import (
    MAX_LIST_FINDINGS,
    EngagementRepo,
    FindingRepo,
    MetricsRepo,
    PersistenceSink,
    RunRepo,
    ServiceRepo,
)
from .scope import sign_scope
from .store import Store
from .uploads import UploadError, save_and_extract

# Agent runtime lives in a sibling package; the single-host image installs both.
from runtime.agent import DEFAULT_MISSION, ORCHESTRATOR_MISSION, run_agent
from runtime.llm.config import get_provider
from runtime.orchestrator import run_scan
from runtime.registry import ToolRegistry
from runtime.sandbox import DockerSandbox
from runtime.subagents import SPECIALISTS, specialist_mission, specialist_registry
from runtime.toolset import all_tools, select_tools

# Phase 7: authentication + per-tenant rate limiting. With no EYE_API_KEYS set, auth is open dev mode.
authenticator = Authenticator()
limiter = RateLimiter()


def get_principal(x_api_key: str | None = Header(default=None)) -> Principal:
    principal = authenticator.principal_for(x_api_key)
    if principal is None:
        raise HTTPException(401, "missing or invalid API key")
    return principal


def require(minimum: str):
    """Dependency factory enforcing a minimum role on an endpoint."""

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not has_role(principal, minimum):
            raise HTTPException(403, f"requires role >= {minimum}")
        return principal

    return _dep


# Routes that answer without a key. Only liveness — it exposes no engagement data.
PUBLIC_PATHS = frozenset({"/health"})


def require_viewer_unless_public(
    request: Request, x_api_key: str | None = Header(default=None)
) -> Principal | None:
    """S1: the app-wide authentication floor.

    Registered as a router-level dependency below, so *every* route — including one added tomorrow
    that forgets to declare a dependency — requires at least a `viewer` key. Endpoints that need more
    still declare `require("operator")` on top; endpoints that need the principal still inject it.

    The exemption is done by path rather than with `dependencies=[]` on the route, because FastAPI
    *extends* the router's dependency list with the route's (`APIRouter.add_api_route`) — an empty
    route-level list removes nothing, so the plan's `dependencies=[]` exemption would have left
    /health authenticated and broken keyed deployments' liveness probes.
    """
    if (request.url.path.rstrip("/") or "/") in PUBLIC_PATHS:
        return None
    principal = authenticator.principal_for(x_api_key)
    if principal is None:
        raise HTTPException(401, "missing or invalid API key")
    if not has_role(principal, "viewer"):
        raise HTTPException(403, "requires role >= viewer")
    return principal


# The router-level dependency below is the authentication floor for the *API* routes — but it does
# not reach FastAPI's own docs endpoints. `FastAPI.setup()` registers /docs, /redoc and /openapi.json
# with `add_route()`, producing plain Starlette `Route` objects, while router-level `dependencies`
# are only applied to the `APIRoute`s built by `add_api_route()`. So those three answered 200 to an
# unauthenticated caller and disclosed the full schema — every path, parameter and model — which is
# a free reconnaissance map of the control plane.
#
# Outside development they are simply not mounted. Passing None is what actually removes the route;
# there is no dependency to attach, so gating the URL is the only closed answer. In development the
# stack usually runs in open-dev-mode anyway (no EYE_API_KEYS), where authenticating them would be
# meaningless, and the interactive docs are genuinely useful there.
_DOCS_ENABLED = is_development()

app = FastAPI(
    title="Pinkeye — Control Plane",
    dependencies=[Depends(require_viewer_unless_public)],
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)

# S3: CORS is an allowlist, not a wildcard. Read endpoints expose findings, transcripts, and signed
# scopes, so any origin allowed here can read them from a browser session that can reach the API.
_CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("EYE_CORS_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["X-API-Key", "Content-Type"],
)

graph = GraphClient()
db = Database(settings.postgres_dsn)
engagements = EngagementRepo(db)
runs = RunRepo(db)
findings = FindingRepo(db)
services = ServiceRepo(db)
metrics = MetricsRepo(db)
persistence = PersistenceSink(db)

# In-memory fallback so the API keeps working when Postgres is down (dev convenience).
store = Store()
TOOLS = {t.name: t for t in all_tools(db)}

# Live run-event stream powering the chat interface. Best-effort persisted to Postgres (migration
# 0006) with an in-memory ring buffer as the fast path for SSE tailing + reconnect.
run_events = RunEventStore(db)
# Reverse channel for the interactive chat: carries an operator's reply from POST /runs/{id}/reply
# into the run's background thread, which blocks inside the agent's ask_user tool.
run_inbox = RunInbox()

# Cross-run network memory (the "brain"): the durable, differential map fed back to the agent and
# surfaced to the UI. Backed by Neo4j (topology) + Postgres (audit-grade diff log). It can never
# widen a scope — it is guidance and record-keeping only.
memory = NetworkMemory(graph, db)

# One retirement signal for all of a finished run's in-process state. The event store already tracks
# when a run reaches a terminal status and expires its buffer after a grace period; these hooks hang
# the other per-run maps off that same moment, so they expire together instead of each relying on its
# own idle sweep (and `Store.runs`, which has no sweep of its own, expires at all).
#
# Nothing durable is discarded: the transcript lives in `run_events`, the diff log in
# `network_observations`, and runs/engagements in Postgres — each of these maps re-reads or
# re-derives on demand. Hooks are best-effort; `RunEventStore` swallows their exceptions so a
# failure here can never disturb the event stream.
run_events.on_retire(run_inbox.retire)
run_events.on_retire(memory.retire_run)
# Two-arg pop: a run that was never cached here (or was already evicted) is the normal case, not an
# error — one-arg dict.pop would raise KeyError on every such retirement.
run_events.on_retire(lambda run_id: store.runs.pop(run_id, None))


class _AuditSink:
    """Late-bound audit sink (C14).

    Sink construction needs a live Postgres connection, so doing it at *import* time blocked uvicorn
    from binding a port for the pool's full connect timeout and ran `migrate()` a second time (the
    startup hook already runs it). This holder is handed to runs and endpoints at import, and the real
    sink is bound during startup. Until then — and in tests, which instantiate `TestClient` without a
    lifespan — it degrades to the in-memory sink rather than losing events.
    """

    def __init__(self) -> None:
        self._sink = None
        self._lock = threading.Lock()

    def bind(self, sink) -> None:
        with self._lock:
            self._sink = sink

    def resolve(self):
        sink = self._sink
        if sink is not None:
            return sink
        with self._lock:
            if self._sink is None:
                self._sink = MemoryAuditSink()
            return self._sink

    def append(self, event: AuditEvent) -> None:
        self.resolve().append(event)

    def append_many(self, events) -> None:
        # `append_many` is part of the AuditSink protocol, so every bound sink has it and the run
        # path's batched writes stay batched.
        self.resolve().append_many(events)


audit = _AuditSink()


# B1: agent runs get their own explicitly-sized executor. They used to ride FastAPI's shared
# request threadpool, where a handful of multi-hour interactive runs could starve every sync
# endpoint — including /health. Capacity is now a tunable number, and back-pressure is visible
# (503 + Retry-After) instead of a run silently stuck in "queued".
MAX_CONCURRENT_RUNS = max(1, int(os.getenv("EYE_MAX_CONCURRENT_RUNS", "8")))
_RUN_POOL = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_RUNS, thread_name_prefix="eye-run")
# Counts in-flight runs; the executor's own queue is unbounded and unobservable, so admission is
# controlled here rather than by letting work pile up invisibly behind the workers.
_RUN_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_RUNS)
_RUN_RETRY_AFTER = os.getenv("EYE_RUN_RETRY_AFTER", "30")

# SSE safety cap. The old hard-coded 30 minutes silently closed the stream mid-run for orchestrator
# profiles (several specialist passes plus a 600 s ask_user block). 0 disables the cap.
SSE_MAX_SECONDS = float(os.getenv("EYE_SSE_MAX_SECONDS", str(6 * 60 * 60)))
# Fallback heartbeat for the SSE tail. Since B4 the generator is woken by `emit`, so this only bounds
# how long a stream can sit before re-checking client disconnect and the duration cap.
SSE_HEARTBEAT_SECONDS = float(os.getenv("EYE_SSE_HEARTBEAT_SECONDS", "2.0"))
# Each tailing client parks one thread in `Event.wait`. Keep those off both the request threadpool
# and the run pool, so a wall of dashboard tabs can never crowd out request handling or a run.
_SSE_POOL = ThreadPoolExecutor(
    max_workers=max(1, int(os.getenv("EYE_SSE_WAIT_THREADS", "128"))),
    thread_name_prefix="eye-sse",
)


@app.on_event("startup")
def _startup():
    # S6: refuse to serve with the open dev-mode authenticator outside development. With no
    # EYE_API_KEYS configured every request is a default-tenant admin, which makes the RBAC above
    # decorative — that must be a development-only convenience, never a silent production default.
    assert_secure_authentication(authenticator.open_dev_mode)

    # B1: sync request handlers keep their own (larger) pool now that runs no longer share it.
    try:
        import anyio.to_thread

        anyio.to_thread.current_default_thread_limiter().total_tokens = int(
            os.getenv("EYE_API_THREADS", "60")
        )
    except Exception:
        pass

    # Apply DB migrations and graph schema; both tolerate the backends not being ready yet.
    try:
        db.migrate()
    except Exception:
        pass
    # C14: one migrate() call, then bind the durable audit sink; in-memory if Postgres is unreachable.
    try:
        with db.connection():
            pass
        audit.bind(PostgresAuditSink(db))
    except Exception:
        audit.bind(MemoryAuditSink())
    # Graph schema still tolerates Neo4j not being up yet, but the failure is no longer silent:
    # apply_schema now reports which statements failed, and a constraint that cannot be created
    # (e.g. service_key on a database with pre-existing duplicates) leaves the graph unindexed and
    # every MERGE doing a label scan. Swallowing that diagnostic is how it stays unnoticed.
    try:
        graph.apply_schema(os.getenv("EYE_GRAPH_SCHEMA", "/app/graph/schema.cypher"))
    except Exception as exc:
        traceback.print_exc()
        print(f"[startup] graph schema not fully applied: {exc}", flush=True)
    try:
        # B13: one-time backfill of engagement->host DISCOVERED edges for data written before linking
        # existed. Self-gated on EYE_GRAPH_BACKFILL_LINKS and a no-op by default — current writes
        # MERGE that edge inline, and the query scans every IP/Endpoint in the database.
        graph.link_engagement_hosts()
    except Exception:
        pass


@app.on_event("shutdown")
def _shutdown():
    # Stop accepting new runs; in-flight ones are not waited on (they die with the process today).
    try:
        _RUN_POOL.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    try:
        _SSE_POOL.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    # Close any warm pooled MCP sessions so their sibling containers never leak past the API process.
    try:
        from runtime.mcp import shutdown_pool

        shutdown_pool()
    except Exception:
        pass


# Owner tenant of every engagement this process has written, mirroring `engagements.tenant_id`. The
# in-memory `Store` fallback has no concept of a tenant, so without this the degraded path would hand
# one tenant another's engagement the moment Postgres is unreachable. Only ever holds ids created (or
# re-saved) here, which is exactly the set `store` can answer for.
_engagement_tenants: dict[str, str] = {}


def _read_tenant(principal: Principal | None) -> str | None:
    """The tenant filter to apply to a read, or None for "no filter" (S4).

    The rule: **`admin` reads across tenants, `operator` and `viewer` are confined to their own.**
    `has_role` is a rank comparison (viewer < operator < admin), so this is the one rank that sits
    above the write roles — cross-tenant visibility is an operations/support capability, not
    something an engagement operator gets. It also keeps open dev mode working unchanged: with
    `EYE_API_KEYS` unset every request is a default-tenant *admin*, so the filter is None and every
    query is exactly the one it was before this change.
    """
    if principal is None or has_role(principal, "admin"):
        return None
    return principal.tenant_id


def _engagement_owner(engagement_id: str) -> str | None:
    """Which tenant owns an engagement, or None if we cannot establish it."""
    try:
        owner = engagements.tenant_of(engagement_id)
    except Exception:
        owner = None
    return owner or _engagement_tenants.get(engagement_id)


def _tenant_for_engagement(engagement_id: str, principal: Principal) -> str:
    """The tenant that rows written for this engagement are stamped with.

    The engagement's own tenant wins over the caller's: for a non-admin the two are necessarily equal
    (the engagement would not have resolved otherwise), and for an admin acting on another tenant's
    engagement the rows must stay with the engagement — that is the relation migration 0009 backfills
    along, and the invariant every tenant-filtered read depends on.
    """
    return _engagement_owner(engagement_id) or principal.tenant_id


def _engagement_visible(engagement_id: str, principal: Principal | None) -> bool:
    """Whether `principal` may read data belonging to this engagement.

    Denies only when the engagement is *positively known* to belong to another tenant. An id we
    cannot resolve is left alone rather than 404'd, because the engagement-scoped read endpoints
    already answer for unknown ids with empty state and turning that into an error would change
    behaviour far beyond tenancy.
    """
    tenant = _read_tenant(principal)
    if tenant is None:
        return True
    owner = _engagement_owner(engagement_id)
    return owner is None or owner == tenant


def _require_engagement_visible(engagement_id: str, principal: Principal | None) -> None:
    # 404, not 403: confirming that an engagement exists is itself a cross-tenant disclosure.
    if not _engagement_visible(engagement_id, principal):
        raise HTTPException(404, "engagement not found")


def _save_engagement(e: Engagement, tenant_id: str = "default") -> None:
    store.add_engagement(e)  # always cache
    _engagement_tenants[e.id] = tenant_id
    try:
        engagements.save(e, tenant_id)
    except Exception:
        pass


def _load_engagement(engagement_id: str, tenant_id: str | None = None) -> Engagement | None:
    """Resolve an engagement, optionally confined to one tenant (None = no filter).

    Both branches are filtered: the durable read pushes the tenant into SQL, and the in-memory
    fallback consults `_engagement_tenants`. The fallback treats an unrecorded id as visible, which
    is safe because `store` only holds engagements this process saved — and `_save_engagement`
    records the owner for every one of those.
    """
    try:
        e = engagements.get(engagement_id, tenant_id)
        if e:
            return e
    except Exception:
        pass
    cached = store.engagements.get(engagement_id)
    if cached is None:
        return None
    if tenant_id is not None and _engagement_tenants.get(engagement_id, tenant_id) != tenant_id:
        return None
    return cached


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _run_payload(source) -> dict:
    """One run shape for every code path (C5).

    `RunRepo.get` hands back a row mapping while the in-memory `Store` holds a pydantic `Run`, so the
    two branches of `GET /runs/{id}` used to serialize differently (different keys, different status
    encoding). Normalizing here means clients see one schema regardless of which store answered, and
    it stays correct if the repo is later changed to return a model.
    """
    if hasattr(source, "model_dump"):
        data = source.model_dump(mode="json")
    else:
        data = dict(source)
    status = data.get("status")
    return {
        "id": data.get("id"),
        "engagement_id": data.get("engagement_id"),
        "target": data.get("target"),
        "status": getattr(status, "value", status),
        "created_at": _iso(data.get("created_at")),
        "updated_at": _iso(data.get("updated_at")),
    }


def _engagement_id_for_run(run_id: str) -> str | None:
    run = store.runs.get(run_id)
    if run is not None:
        return run.engagement_id
    try:
        row = runs.get(run_id)
    except Exception:
        return None
    if not row:
        return None
    return _run_payload(row).get("engagement_id")


class CreateEngagement(BaseModel):
    name: str
    allowed_cidrs: list[str] = []
    allowed_domains: list[str] = []
    allowed_artifacts: list[str] = []  # source paths/repos the SAST tools may analyze
    window_hours: int = 24
    max_intensity: Intensity = Intensity.normal
    # Intrusive capabilities, off by default. Setting these is an explicit authorization decision.
    allow_exploit: bool = False
    allow_credential_attacks: bool = False


class CreateRun(BaseModel):
    target: str
    tool: str = "nmap"
    intensity: Intensity = Intensity.light
    # "scan" runs one tool deterministically; "agent" lets the LLM plan multi-step recon.
    mode: str = "scan"
    # Agent-mode free-text objective from the chat UI. Combined with DEFAULT_MISSION as guidance; it
    # is NOT authorization — every tool call is still checked against the signed scope.
    objective: str | None = None
    # Optional auth profile for authenticated DAST (e.g. {"header_name": "Authorization",
    # "value_ref": "app-token"}); value_ref resolves from secrets so credentials aren't stored here.
    auth: dict | None = None
    # Agent-mode "tool library": the subset of tools the planner may use this run. None/empty = all.
    # A capability restriction only — an unchecked tool is never offered, so it cannot run; the scope
    # guard and offensive-flag gate still apply on top of whatever remains.
    enabled_tools: list[str] | None = None
    # Agent-mode profile (who drives the assessment). None/"full" = an orchestrator that delegates to
    # specialist sub-agents on demand; a specialist name (recon/dast/sast/intel/exploit/credentials)
    # runs that single focused specialist directly; "flat" = the legacy single generalist agent.
    profile: str | None = None


class CypherQuery(BaseModel):
    cypher: str


@app.get("/health")
def health():
    """The only unauthenticated route (listed in PUBLIC_PATHS), so liveness/readiness probes need no
    key. It exposes no engagement data."""
    return {"status": "ok"}


@app.get("/tools")
def list_tools():
    """The tool library the UI renders as checkboxes: every registered tool with the metadata needed
    to group and label it. `requires_flag` marks offensive tools that also need a signed scope flag."""
    return [
        {
            "name": t.name,
            "description": getattr(t, "description", ""),
            "surface": getattr(t, "surface", "network"),
            "requires_flag": getattr(t, "requires_flag", None),
            "mcp": getattr(t, "mcp", None) is not None,
        }
        for t in TOOLS.values()
    ]


@app.get("/profiles")
def list_profiles():
    """Agent profiles the UI offers in the launcher: the orchestrator ("full"), one per specialist
    sub-agent, and the legacy generalist ("flat"). `gated_flag` marks specialists that also need a
    signed scope flag (offered but inert without it)."""
    specialists = [
        {"name": s.kind, "stage": s.stage, "description": s.summary, "gated_flag": s.gated_flag}
        for s in SPECIALISTS.values()
    ]
    return {
        "profiles": [
            {"name": "full", "stage": None, "gated_flag": None,
             "description": "Orchestrator — delegates to specialist sub-agents on demand."},
            *specialists,
            {"name": "flat", "stage": None, "gated_flag": None,
             "description": "Single generalist agent (legacy)."},
        ]
    }


@app.get("/cve")
def cve_lookup(product: str, version: str | None = None):
    # Offline CVE lookup for humans/UI; the agent uses the cve_lookup tool for the same data.
    from .cve_db import CveRepo

    try:
        return CveRepo(db).lookup(product, version)
    except Exception as exc:
        raise HTTPException(503, f"cve database unavailable: {exc}")


@app.post("/engagements")
def create_engagement(body: CreateEngagement, principal: Principal = Depends(require("operator"))):
    now = datetime.now(timezone.utc)
    scope = Scope(
        allowed_cidrs=body.allowed_cidrs,
        allowed_domains=body.allowed_domains,
        allowed_artifacts=body.allowed_artifacts,
        not_before=now,
        not_after=now + timedelta(hours=body.window_hours),
        max_intensity=body.max_intensity,
        allow_exploit=body.allow_exploit,
        allow_credential_attacks=body.allow_credential_attacks,
    )
    scope.signature = sign_scope(scope)  # bind the authorization boundary at creation time
    engagement = Engagement(id=str(uuid.uuid4()), name=body.name, scope=scope)
    _save_engagement(engagement, principal.tenant_id)
    try:
        graph.upsert_engagement(engagement.id, engagement.name)
    except Exception:
        pass
    return engagement


@app.get("/engagements")
def list_engagements(principal: Principal = Depends(get_principal)):
    # C4: merge both stores instead of choosing one. `_save_engagement` writes to memory *and* the DB
    # and swallows DB failures, so a reachable-but-empty Postgres used to make engagements that
    # `GET /engagements/{id}` still resolves disappear from the index. The DB copy wins on conflict.
    #
    # S4: both halves are tenant-filtered — the durable half in SQL, the cached half against the
    # owner map — so the index never lists an engagement `GET /engagements/{id}` would refuse.
    tenant = _read_tenant(principal)
    merged: dict[str, Engagement] = {
        eid: e
        for eid, e in store.engagements.items()
        if tenant is None or _engagement_tenants.get(eid, tenant) == tenant
    }
    try:
        for e in engagements.list(tenant):
            merged[e.id] = e
    except Exception:
        pass
    items = list(merged.values())
    try:
        items.sort(key=lambda e: e.created_at, reverse=True)
    except TypeError:
        pass  # mixed naive/aware timestamps across the two stores — order is cosmetic, don't 500
    return items


@app.get("/engagements/{engagement_id}")
def get_engagement(engagement_id: str, principal: Principal = Depends(get_principal)):
    # The response carries the signed scope, so a cross-tenant hit here leaks the authorization
    # boundary itself, not just metadata.
    eng = _load_engagement(engagement_id, _read_tenant(principal))
    if not eng:
        raise HTTPException(404, "engagement not found")
    return eng


@app.post("/engagements/{engagement_id}/sast/upload")
async def upload_sast_source(
    engagement_id: str,
    request: Request,
    filename: str = "upload.zip",
    principal: Principal = Depends(require("operator")),
):
    """Ingest a codebase to statically analyze: the raw archive (zip / tar / tar.gz) or a single
    source file is POSTed as the request body, with `?filename=` naming it. We extract it into the
    upload root, then authorize exactly that extracted directory by adding it to the engagement's
    signed scope (allowed_artifacts) and re-signing.

    Uploading a codebase to scan IS the authorization decision — it is operator-gated and audited —
    so extending the scope to the extracted path is deliberate, and it can only ever *add* a local
    source path (surface="artifact"); it never touches network CIDRs/domains or any offensive flag.
    The returned `path` is what a subsequent SAST run targets (semgrep/Snyk, gitleaks, trivy, or the
    `sast` agent profile). The path is chosen so it resolves identically for the sandbox mount and any
    MCP SAST sibling (see settings.upload_root)."""
    if not limiter.allow(principal.tenant_id):
        raise HTTPException(429, "rate limit exceeded for tenant")
    eng = _load_engagement(engagement_id, _read_tenant(principal))
    if not eng:
        raise HTTPException(404, "engagement not found")
    # Re-signing the scope must not move the engagement between tenants; an admin may legitimately be
    # acting on another tenant's engagement, and ownership stays where it is.
    owner_tenant = _tenant_for_engagement(engagement_id, principal)

    data = await request.body()
    try:
        result = save_and_extract(settings.upload_root, engagement_id, filename, data)
    except UploadError as exc:
        raise HTTPException(400, str(exc))
    except OSError as exc:
        raise HTTPException(500, f"could not store upload: {exc}")

    if result.file_count == 0:
        raise HTTPException(400, "archive contained no files to analyze")

    # Authorize the extracted directory: add it to allowed_artifacts and re-sign the scope. The guard
    # prefix-matches, so the run's target (this exact dir, or a file under it) is now in scope.
    scope = eng.scope
    if result.path not in scope.allowed_artifacts:
        scope.allowed_artifacts = [*scope.allowed_artifacts, result.path]
        scope.signature = sign_scope(scope)
        _save_engagement(eng, owner_tenant)

    # Record the authorization decision: an upload extends the signed scope, so it belongs in the same
    # audit trail as every scope check. There is no run yet, so it is keyed to a synthetic upload id.
    try:
        audit.append(AuditEvent(
            engagement_id=engagement_id, run_id=f"upload:{uuid.uuid4().hex[:12]}",
            type=EventType.scope_decision, tool="sast_upload", target=result.path, allowed=True,
            detail=f"authorized uploaded {result.kind} ({result.file_count} files) for static analysis",
        ))
    except Exception:
        pass

    return {
        "path": result.path,
        "kind": result.kind,
        "file_count": result.file_count,
        "total_bytes": result.total_bytes,
        "artifact": result.path,
    }


@app.post("/engagements/{engagement_id}/runs")
def create_run(engagement_id: str, body: CreateRun,
               principal: Principal = Depends(require("operator"))):
    if not limiter.allow(principal.tenant_id):
        raise HTTPException(429, "rate limit exceeded for tenant")
    eng = _load_engagement(engagement_id, _read_tenant(principal))
    if not eng:
        raise HTTPException(404, "engagement not found")
    tool = TOOLS.get(body.tool)
    if not tool:
        raise HTTPException(400, f"unknown tool: {body.tool}")

    # Tool-library selection: narrow the planner's registry to the operator's checked tools (all if
    # unspecified). Capability restriction only — the scope guard/flag gate still apply to the rest.
    planner_tools = select_tools(list(TOOLS.values()), body.enabled_tools)
    # C15: a selection that matches nothing must fail closed. `select_tools` widens to the full
    # library in that case, so an operator who deselects everything but a renamed tool would silently
    # get every tool, gated ones included. Deny-by-default is the house rule; reject at the boundary.
    if body.enabled_tools and not planner_tools:
        raise HTTPException(400, f"none of the requested tools exist: {body.enabled_tools}")

    # B1: admission control, taken before any run state exists so a rejected request leaves no
    # phantom run behind. A full executor means every one of EYE_MAX_CONCURRENT_RUNS slots is busy;
    # queueing would hide that behind a run stuck in "queued" forever, so say so instead. The slot is
    # held until `_launch` finishes (see its `finally`).
    if not _RUN_SLOTS.acquire(blocking=False):
        raise HTTPException(
            503,
            f"run capacity reached ({MAX_CONCURRENT_RUNS} concurrent runs); retry shortly",
            headers={"Retry-After": _RUN_RETRY_AFTER},
        )
    launched = False
    try:
        run = Run(id=str(uuid.uuid4()), engagement_id=engagement_id, target=body.target)
        store.add_run(run)

        # C11/S4: bind the tenant to the run, once, here. Everything the run writes goes through
        # `run_sink`, a view of the process-wide sink that stamps `tenant_id` on every row — so the
        # orchestrator and the agent loop keep receiving one opaque `db` object and stay unaware that
        # tenancy exists. Threading a tenant argument through `execute_tool_step` instead would have
        # put a storage concern into the security-critical step function and broken every test double
        # that implements the sink's methods positionally.
        run_tenant = _tenant_for_engagement(engagement_id, principal)
        run_sink = persistence.for_tenant(run_tenant)
        try:
            # `tool`/`intensity` exist since migration 0001 and had no writer; in agent mode the
            # planner picks its own tools, so there is no single tool to attribute the run to.
            runs.save(run, run_tenant,
                      tool=None if body.mode == "agent" else body.tool,
                      intensity=body.intensity.value)
        except Exception:
            pass

        # Execute off the request thread. The sandbox is built inside the task, not here, so a Docker
        # problem fails the run (not the API request); the scope guard still runs first in either path.
        context = {"auth": body.auth} if body.auth else None

        # Agent profile: who drives the assessment. "full" (default) = an orchestrator delegating to
        # specialist sub-agents; a specialist name runs that single focused specialist directly over
        # the selected tool pool; "flat" = the legacy single generalist agent. Presentation/capability
        # choice only — the scope guard and offensive-flag gate are unchanged for every path.
        profile = (body.profile or "full").strip().lower()
        if body.mode == "agent" and profile not in ({"full", "flat"} | set(SPECIALISTS)):
            raise HTTPException(400, f"unknown profile: {body.profile}")
        if profile in SPECIALISTS:
            base_mission, agent_registry, specialist_pool = (
                specialist_mission(profile), specialist_registry(profile, planner_tools), None)
        elif profile == "flat":
            base_mission, agent_registry, specialist_pool = (
                DEFAULT_MISSION, ToolRegistry(planner_tools), None)
        else:  # "full" orchestrator: registry unused (specs come from the specialist sub-agents)
            base_mission, agent_registry, specialist_pool = (
                ORCHESTRATOR_MISSION, ToolRegistry([]), planner_tools)

        # Combine the operator's objective with the chosen mission. Guidance only, never authorization.
        mission = base_mission
        if body.objective and body.objective.strip():
            mission = f"{base_mission}\n\nEngagement objective: {body.objective.strip()}"

        def _launch():
            try:
                sandbox = DockerSandbox()
                if body.mode == "agent":
                    run_agent(eng, run, get_provider("planner"), agent_registry,
                              sandbox, graph, audit, run_sink, mission=mission, context=context,
                              events=run_events, memory=memory, inbox=run_inbox,
                              specialist_pool=specialist_pool)
                else:
                    run_scan(eng, run, tool, body.intensity, sandbox, graph, audit, run_sink,
                             context, memory=memory)
            except Exception as exc:
                # Any setup failure (e.g. Docker unavailable, provider unreachable) must mark the run
                # failed AND be visible — never leave it stuck in "running" with silent logs.
                traceback.print_exc()  # to the container log
                run.status = RunStatus.failed
                try:
                    run_sink.set_run_status(run.id, RunStatus.failed.value)
                except Exception:
                    pass
                # Emit a terminal status + error so the UI/SSE stops waiting and shows the cause.
                try:
                    run_events.emit(run.id, engagement_id, "error", scope="launch",
                                    message=f"{type(exc).__name__}: {exc}")
                    run_events.emit(run.id, engagement_id, "status", status=RunStatus.failed.value)
                except Exception:
                    pass
            finally:
                _RUN_SLOTS.release()  # free the capacity slot for the next caller

        _RUN_POOL.submit(_launch)
        launched = True
        return _run_payload(run)
    finally:
        if not launched:
            # Nothing will ever run `_launch`'s `finally`, so the slot has to come back here.
            _RUN_SLOTS.release()


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    # C5: both branches go through `_run_payload`, so the DB and the in-memory fallback answer with
    # the same keys and the same status encoding.
    try:
        row = runs.get(run_id)
        if row:
            return _run_payload(row)
    except Exception:
        pass
    run = store.runs.get(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return _run_payload(run)


# ---- live run event stream (chat interface) ----

@app.get("/runs/{run_id}/transcript")
def run_transcript(run_id: str):
    """Full ordered transcript of a run's events, for replay and reconnect. A client reconnecting
    fetches this, renders it, then tails /events?after=<last seq> for anything newer."""
    return {"events": [e.model_dump(mode="json") for e in run_events.all_events(run_id)]}


class RunReply(BaseModel):
    text: str


@app.post("/runs/{run_id}/reply")
def run_reply(run_id: str, body: RunReply, principal: Principal = Depends(require("operator"))):
    """Deliver the operator's chat reply to a run waiting on an `ask_user` prompt. Guidance/permission
    only — it re-enters the planner as a tool result and can never widen scope; the scope guard and
    offensive-flag gate still decide what any subsequent tool call may do. Delivery is fire-and-forget:
    if the run isn't currently waiting, the message queues until its next ask (or is harmlessly unused).

    S2: operator-gated and audited. A reply cannot widen scope, but `ask_user(kind="permission")` is
    the human-in-the-loop approval the exploit / post_exploit / credential_attack missions require
    before acting, so on an engagement whose signed scope already carries those flags this reply *is*
    the approval. It therefore belongs to a named principal and lands in the same defensible record as
    the scope decisions it authorizes."""
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(400, "reply text is required")
    run_inbox.deliver(run_id, text)
    try:
        audit.append(AuditEvent(
            engagement_id=_engagement_id_for_run(run_id) or "unknown",
            run_id=run_id, type=EventType.scope_decision, tool="ask_user",
            target="operator_reply", allowed=True,
            detail=f"operator {principal.tenant_id}/{principal.role} replied to run {run_id}",
        ))
    except Exception:
        pass
    return {"ok": True}


@app.get("/runs/{run_id}/events")
async def run_events_stream(run_id: str, request: Request, after: int = 0):
    """Server-Sent Events tail of a run. Reads the run-event store by seq (memory-first, Postgres
    fallback) rather than bridging the run's background thread into the event loop — which also gives
    replay/reconnect for free via ?after=<seq>. Closes cleanly on terminal status, client disconnect,
    or the configurable safety timeout.

    B4: the generator blocks on the run's `threading.Event` instead of polling, so an emit wakes it
    immediately and an idle stream costs nothing. `poll_interval` survives only as a heartbeat that
    re-checks client disconnect and the duration cap.
    """
    poll_interval = SSE_HEARTBEAT_SECONDS
    max_duration = SSE_MAX_SECONDS  # 0 disables the cap

    async def gen():
        last = after
        started = time.monotonic()
        waiter = run_events.waiter(run_id)
        while True:
            if await request.is_disconnected():
                break
            # Clear *before* draining: an emit landing between the drain and the wait leaves the
            # event set, so the next wait returns at once rather than losing the wakeup.
            waiter.clear()
            terminal = False
            # Off the event loop: since C6, `events_after` falls back to Postgres when this process
            # has no buffer for the run (an API restart, or a run executing in a worker). That is a
            # blocking driver call, and on the loop thread it would stall every other request in the
            # process for the duration of the query — not just this stream.
            drained = await asyncio.get_running_loop().run_in_executor(
                _SSE_POOL, run_events.events_after, run_id, last
            )
            for ev in drained:
                last = ev.seq
                yield f"id: {ev.seq}\ndata: {json.dumps(ev.model_dump(mode='json'))}\n\n"
                if ev.is_terminal():
                    terminal = True
            if terminal:
                break  # all events up to and including the terminal status have been drained
            if max_duration and time.monotonic() - started > max_duration:
                break
            await asyncio.get_running_loop().run_in_executor(
                _SSE_POOL, waiter.wait, poll_interval
            )

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---- network map (graph) ----

@app.get("/map")
def full_map(limit: int = 1000):
    # Cross-engagement network map, capped so a large graph can't return an unbounded payload.
    return graph.get_graph(None, limit=limit)


@app.get("/engagements/{engagement_id}/graph")
def engagement_graph(engagement_id: str, limit: int = 1000,
                     principal: Principal = Depends(get_principal)):
    # The graph itself carries no tenant property (see the report's remaining-holes note), so tenancy
    # is enforced one level up: you may only ask for the sub-graph of an engagement you can see.
    _require_engagement_visible(engagement_id, principal)
    return graph.get_graph(engagement_id, limit=limit)


@app.post("/engagements/{engagement_id}/graph/query")
def graph_query(engagement_id: str, body: CypherQuery,
                principal: Principal = Depends(get_principal)):
    """Operator Cypher, scoped to one engagement.

    C3: the path parameter used to be decorative — the query ran against the whole graph, so a URL
    that looked engagement-scoped was a cross-engagement (and cross-tenant) read primitive. The id is
    now bound as `$eid` and the query must reference it, e.g.
    `MATCH (n:IP {engagement_id: $eid}) RETURN n`. That is a structural boundary the caller cannot
    spell around with a literal, unlike the lexical `is_read_only_cypher` write guard.
    """
    ok, reason = is_read_only_cypher(body.cypher)
    if not ok:
        raise HTTPException(400, f"rejected: {reason}")
    if "$eid" not in body.cypher:
        raise HTTPException(
            400,
            "rejected: the query must scope itself to this engagement via the $eid parameter "
            "(e.g. MATCH (n:IP {engagement_id: $eid}) RETURN n)",
        )
    if not _load_engagement(engagement_id, _read_tenant(principal)):
        raise HTTPException(404, "engagement not found")
    try:
        return {"rows": graph.run_read_query(body.cypher, {"eid": engagement_id})}
    except Exception as exc:
        raise HTTPException(400, f"query error: {exc}")


# ---- queryable findings, entities, and KPIs ----

@app.get("/engagements/{engagement_id}/findings")
def query_findings(
    engagement_id: str,
    severity: str | None = None,
    category: str | None = None,
    state: str | None = None,
    cve: str | None = None,
    target: str | None = None,
    q: str | None = None,
    limit: int = 200,
    principal: Principal = Depends(get_principal),
):
    filters = FindingFilters(
        severity=severity, category=category, state=state, cve=cve, target=target, q=q, limit=limit
    )
    try:
        # S4: the `tenant_id = %s` clause build_findings_query has always emitted finally gets a
        # value. It is a real filter now that the write path stamps the column (C11).
        return findings.query(engagement_id, filters, _read_tenant(principal))
    except Exception as exc:
        raise HTTPException(503, f"findings store unavailable: {exc}")


@app.get("/engagements/{engagement_id}/entities")
def search_entities(engagement_id: str, q: str, limit: int = 100,
                    principal: Principal = Depends(get_principal)):
    # `ServiceRepo.search` is not tenant-aware, so the boundary is drawn at the engagement instead.
    _require_engagement_visible(engagement_id, principal)
    try:
        return services.search(engagement_id, q, limit)
    except Exception as exc:
        raise HTTPException(503, f"entity store unavailable: {exc}")


@app.get("/engagements/{engagement_id}/metrics")
def engagement_metrics(engagement_id: str, principal: Principal = Depends(get_principal)):
    # As above: MetricsRepo aggregates by engagement, so the engagement is the unit of authorization.
    _require_engagement_visible(engagement_id, principal)
    try:
        return metrics.kpis(engagement_id)
    except Exception as exc:
        raise HTTPException(503, f"metrics store unavailable: {exc}")


# ---- cross-run network memory (the "brain") ----

@app.get("/engagements/{engagement_id}/memory")
def engagement_memory(engagement_id: str, principal: Principal = Depends(get_principal)):
    """Current differential map: devices, their service clusters, and exploitable/target flags."""
    _require_engagement_visible(engagement_id, principal)
    return memory.snapshot(engagement_id)


@app.get("/engagements/{engagement_id}/changes")
def engagement_changes(engagement_id: str, run_id: str,
                       principal: Principal = Depends(get_principal)):
    """What a specific run changed vs the remembered map — the "changes since last run" feed."""
    _require_engagement_visible(engagement_id, principal)
    return memory.deltas_for_run(run_id).to_dict()


# ---- Phase 5: correlation, validation, reporting ----

@app.get("/engagements/{engagement_id}/chains")
def get_chains(engagement_id: str, principal: Principal = Depends(get_principal)):
    """Correlate the current findings into attack chains. C2: a pure read — the graph write that
    used to run here made every dashboard render mint a fresh AttackChain node per chain. Chains are
    materialized into the graph by POST /engagements/{id}/validate instead."""
    try:
        # C8: page the full set. Correlation groups by host and by shared CWE, so a truncated input
        # doesn't just omit chains — it can silently break a chain that the dropped findings belonged
        # to, reporting a weaker attack path than the data supports.
        return correlate(findings.list_findings(
            engagement_id, all=True, tenant_id=_read_tenant(principal)))
    except Exception as exc:
        raise HTTPException(503, f"findings store unavailable: {exc}")


@app.post("/engagements/{engagement_id}/validate")
def validate_findings(engagement_id: str, principal: Principal = Depends(require("operator"))):
    """Promote findings corroborated across independent runs from suspected -> confirmed, then
    materialize the resulting attack chains into the graph so the map can highlight them.

    S2/C2: this is the write half of the correlation flow, so it is operator-gated and it is the one
    place chains are persisted. Chain ids are deterministic, so the MERGE is genuinely idempotent and
    re-validating updates the existing nodes rather than duplicating them."""
    _require_engagement_visible(engagement_id, principal)
    tenant = _read_tenant(principal)
    try:
        promoted = findings.promote_corroborated(engagement_id)
    except Exception as exc:
        raise HTTPException(503, f"findings store unavailable: {exc}")
    written = 0
    try:
        chains = correlate(findings.list_findings(engagement_id, all=True, tenant_id=tenant))
    except Exception:
        chains = []
    for c in chains:
        try:
            graph.write_attack_chain(c)
            written += 1
        except Exception:
            pass
    return {"promoted": promoted, "chains_written": written}


@app.get("/engagements/{engagement_id}/report", response_class=PlainTextResponse)
def get_report(engagement_id: str, principal: Principal = Depends(get_principal)):
    tenant = _read_tenant(principal)
    eng = _load_engagement(engagement_id, tenant)
    if not eng:
        raise HTTPException(404, "engagement not found")
    try:
        # C8: a report that silently omits findings is worse than one that is slow. Page the whole
        # set, and if the hard ceiling was reached say so in the document itself — an assessment
        # report is a deliverable someone signs off on, so an incomplete one must announce it.
        fs = findings.list_findings(engagement_id, all=True, tenant_id=tenant)
        total = findings.count(engagement_id, tenant_id=tenant)
        kpis = metrics.kpis(engagement_id)
    except Exception as exc:
        raise HTTPException(503, f"store unavailable: {exc}")
    report = generate_report(eng.name, kpis, fs, correlate(fs))
    if total > len(fs):
        report = (
            f"> **INCOMPLETE REPORT** — {len(fs):,} of {total:,} findings included; the remainder "
            f"exceeded the {MAX_LIST_FINDINGS:,}-row ceiling. Narrow the engagement or query the "
            f"findings API directly.\n\n"
        ) + report
    return report
