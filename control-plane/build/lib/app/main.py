"""FastAPI control plane.

Exposes engagement/scope creation, run triggering, the network-map graph, the queryable findings
API, entity search, read-only Cypher, and the dashboard KPIs. Postgres is the durable store; if it
is unreachable the API falls back to an in-memory cache so the single-host dev stack still runs.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .audit import MemoryAuditSink, PostgresAuditSink
from .auth import Authenticator, Principal, has_role
from .config import settings
from .correlation import correlate
from .db.database import Database
from .graph import GraphClient
from .models import Engagement, Intensity, Run, RunStatus, Scope
from .query import FindingFilters, is_read_only_cypher
from .ratelimit import RateLimiter
from .report import generate_report
from .repositories import (
    EngagementRepo,
    FindingRepo,
    MetricsRepo,
    PersistenceSink,
    RunRepo,
    ServiceRepo,
)
from .scope import sign_scope
from .store import Store

# Agent runtime lives in a sibling package; the single-host image installs both.
from runtime.agent import run_agent
from runtime.llm.config import get_provider
from runtime.orchestrator import run_scan
from runtime.registry import ToolRegistry
from runtime.sandbox import DockerSandbox
from runtime.toolset import all_tools

app = FastAPI(title="Codename Eye — Control Plane")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
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


def _make_audit():
    # Prefer the durable pool-based sink; fall back to in-memory if Postgres can't be reached.
    try:
        db.migrate()  # ensure audit_events exists before the sink writes
        with db.connection():
            pass
        return PostgresAuditSink(db)
    except Exception:
        return MemoryAuditSink()


audit = _make_audit()


@app.on_event("startup")
def _startup():
    # Apply DB migrations and graph schema; both tolerate the backends not being ready yet.
    try:
        db.migrate()
    except Exception:
        pass
    try:
        graph.apply_schema(os.getenv("EYE_GRAPH_SCHEMA", "/app/graph/schema.cypher"))
    except Exception:
        pass


def _save_engagement(e: Engagement, tenant_id: str = "default") -> None:
    store.add_engagement(e)  # always cache
    try:
        engagements.save(e, tenant_id)
    except Exception:
        pass


def _load_engagement(engagement_id: str) -> Engagement | None:
    try:
        e = engagements.get(engagement_id)
        if e:
            return e
    except Exception:
        pass
    return store.engagements.get(engagement_id)


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
    # Optional auth profile for authenticated DAST (e.g. {"header_name": "Authorization",
    # "value_ref": "app-token"}); value_ref resolves from secrets so credentials aren't stored here.
    auth: dict | None = None


class CypherQuery(BaseModel):
    cypher: str


@app.get("/health")
def health():
    return {"status": "ok"}


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
def list_engagements():
    try:
        return engagements.list()
    except Exception:
        return list(store.engagements.values())


@app.get("/engagements/{engagement_id}")
def get_engagement(engagement_id: str):
    eng = _load_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    return eng


@app.post("/engagements/{engagement_id}/runs")
def create_run(engagement_id: str, body: CreateRun, background: BackgroundTasks,
               principal: Principal = Depends(require("operator"))):
    if not limiter.allow(principal.tenant_id):
        raise HTTPException(429, "rate limit exceeded for tenant")
    eng = _load_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    tool = TOOLS.get(body.tool)
    if not tool:
        raise HTTPException(400, f"unknown tool: {body.tool}")

    run = Run(id=str(uuid.uuid4()), engagement_id=engagement_id, target=body.target)
    store.add_run(run)
    try:
        runs.save(run)
    except Exception:
        pass

    # Execute off the request thread. The sandbox is built inside the task, not here, so a Docker
    # problem fails the run (not the API request); the scope guard still runs first inside either path.
    context = {"auth": body.auth} if body.auth else None

    def _launch():
        try:
            sandbox = DockerSandbox()
            if body.mode == "agent":
                run_agent(eng, run, get_provider("planner"), ToolRegistry(list(TOOLS.values())),
                          sandbox, graph, audit, persistence, context=context)
            else:
                run_scan(eng, run, tool, body.intensity, sandbox, graph, audit, persistence, context)
        except Exception:
            # Any setup failure (e.g. Docker unavailable) must mark the run failed, not leave it
            # stuck in "running". Best-effort — the durable store may itself be down.
            run.status = RunStatus.failed
            try:
                persistence.set_run_status(run.id, RunStatus.failed.value)
            except Exception:
                pass

    background.add_task(_launch)
    return run


@app.get("/runs/{run_id}")
def get_run(run_id: str):
    try:
        row = runs.get(run_id)
        if row:
            return row
    except Exception:
        pass
    run = store.runs.get(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return run


# ---- network map (graph) ----

@app.get("/map")
def full_map(limit: int = 1000):
    # Cross-engagement network map, capped so a large graph can't return an unbounded payload.
    return graph.get_graph(None, limit=limit)


@app.get("/engagements/{engagement_id}/graph")
def engagement_graph(engagement_id: str, limit: int = 1000):
    return graph.get_graph(engagement_id, limit=limit)


@app.post("/engagements/{engagement_id}/graph/query")
def graph_query(engagement_id: str, body: CypherQuery):
    ok, reason = is_read_only_cypher(body.cypher)
    if not ok:
        raise HTTPException(400, f"rejected: {reason}")
    try:
        return {"rows": graph.run_read_query(body.cypher)}
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
):
    filters = FindingFilters(
        severity=severity, category=category, state=state, cve=cve, target=target, q=q, limit=limit
    )
    try:
        return findings.query(engagement_id, filters)
    except Exception as exc:
        raise HTTPException(503, f"findings store unavailable: {exc}")


@app.get("/engagements/{engagement_id}/entities")
def search_entities(engagement_id: str, q: str, limit: int = 100):
    try:
        return services.search(engagement_id, q, limit)
    except Exception as exc:
        raise HTTPException(503, f"entity store unavailable: {exc}")


@app.get("/engagements/{engagement_id}/metrics")
def engagement_metrics(engagement_id: str):
    try:
        return metrics.kpis(engagement_id)
    except Exception as exc:
        raise HTTPException(503, f"metrics store unavailable: {exc}")


# ---- Phase 5: correlation, validation, reporting ----

@app.get("/engagements/{engagement_id}/chains")
def get_chains(engagement_id: str):
    # Correlate current findings into attack chains and write them to the graph for the map.
    try:
        chains = correlate(findings.list_findings(engagement_id))
    except Exception as exc:
        raise HTTPException(503, f"findings store unavailable: {exc}")
    for c in chains:
        try:
            graph.write_attack_chain(c)
        except Exception:
            pass
    return chains


@app.post("/engagements/{engagement_id}/validate")
def validate_findings(engagement_id: str):
    # Promote findings corroborated across independent runs from suspected -> confirmed.
    try:
        promoted = findings.promote_corroborated(engagement_id)
    except Exception as exc:
        raise HTTPException(503, f"findings store unavailable: {exc}")
    return {"promoted": promoted}


@app.get("/engagements/{engagement_id}/report", response_class=PlainTextResponse)
def get_report(engagement_id: str):
    eng = _load_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    try:
        fs = findings.list_findings(engagement_id)
        kpis = metrics.kpis(engagement_id)
    except Exception as exc:
        raise HTTPException(503, f"store unavailable: {exc}")
    return generate_report(eng.name, kpis, fs, correlate(fs))
