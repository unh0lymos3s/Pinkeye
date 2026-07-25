"""Repositories over Postgres: durable reads/writes for engagements, runs, findings, services,
plus KPI aggregation and entity search that power the dashboard and query UI.

All SQL uses bound parameters. The PersistenceSink at the bottom is the write interface the
orchestrator calls during a run.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Iterable, Iterator, Optional, Sequence

from .db.database import Database
from .models import Engagement, Finding, Run, Scope
from .query import FindingFilters, build_findings_query

# Page size used when walking every finding of an engagement (reports, correlation). It matches the
# hard clamp in build_findings_query, which is what makes the single-shot path truncate.
LIST_PAGE_SIZE = 1000

# Absolute ceiling on how many findings one walk will produce. `iter_findings` is a generator and so
# is naturally bounded by its consumer, but `list_findings(all=True)` — which /report and /chains use
# — materializes a list, and a full-port sweep across a wide range can yield millions of rows.
# Paging without a ceiling would only trade a silent truncation for an OOM that takes the whole API
# process down, so the walk stops here; callers compare the result length against `count()` to tell a
# complete answer from a capped one.
MAX_LIST_FINDINGS = 50_000


class EngagementRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, e: Engagement, tenant_id: str = "default") -> None:
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO engagements (id, name, scope, created_at, tenant_id) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, scope = EXCLUDED.scope",
                (e.id, e.name, json.dumps(e.scope.model_dump(mode="json")), e.created_at, tenant_id),
            )

    def get(self, engagement_id: str, tenant_id: Optional[str] = None) -> Optional[Engagement]:
        """Fetch one engagement. `tenant_id` scopes the lookup so a principal of another tenant gets
        nothing back rather than a hit, even when it guesses (or is handed) a valid engagement id.
        None means "no tenant filter" — the caller has already decided this read may cross tenants."""
        clauses, params = ["id = %s"], [engagement_id]
        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT id, name, scope, created_at FROM engagements WHERE "
                + " AND ".join(clauses),
                params,
            ).fetchone()
        if not row:
            return None
        return Engagement(id=row[0], name=row[1], scope=Scope(**row[2]), created_at=row[3])

    def list(self, tenant_id: Optional[str] = None) -> list[Engagement]:
        """Every engagement, optionally confined to one tenant (see `get`)."""
        sql = "SELECT id, name, scope, created_at FROM engagements"
        params: list = []
        if tenant_id is not None:
            sql += " WHERE tenant_id = %s"
            params.append(tenant_id)
        sql += " ORDER BY created_at DESC"
        with self._db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [Engagement(id=r[0], name=r[1], scope=Scope(**r[2]), created_at=r[3]) for r in rows]

    def tenant_of(self, engagement_id: str) -> Optional[str]:
        """The tenant that owns an engagement, or None if it isn't in the durable store.

        The engagement row is the authoritative owner of the tenancy relation — migration 0009
        backfills findings/services/runs *from* it — so the run write path stamps rows with this
        rather than with the calling principal's tenant, which for an admin can differ.
        """
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT tenant_id FROM engagements WHERE id = %s", (engagement_id,)
            ).fetchone()
        return row[0] if row else None


class RunRow(Run):
    """A `Run` plus the `updated_at` column the runs table actually carries.

    `GET /runs/{id}` served a raw row mapping when Postgres answered and a pydantic `Run` when the
    in-memory fallback did — two response shapes from one endpoint (C5). Returning a model from both
    paths removes the divergence at the source.

    `updated_at` belongs on `Run` itself, but models.py is owned by another workstream, so it is
    added here by subclassing instead: a `RunRow` *is* a `Run`, so every annotation, isinstance check
    and `response_model=Run` declaration keeps working, and the field can move up to the parent later
    with no change to this repo.
    """

    updated_at: Optional[datetime] = None


class RunRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, run: Run, tenant_id: str = "default", tool: Optional[str] = None,
             intensity: Optional[str] = None) -> None:
        """Persist a run. `tenant_id`/`tool`/`intensity` fill columns that exist in the schema
        (0001, 0002) but had no writer, so tenant filtering was previously a no-op."""
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO runs (id, engagement_id, target, tool, intensity, status, "
                "created_at, updated_at, tenant_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, now(), %s) "
                "ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = now(), "
                "tool = COALESCE(EXCLUDED.tool, runs.tool), "
                "intensity = COALESCE(EXCLUDED.intensity, runs.intensity)",
                (run.id, run.engagement_id, run.target, tool, intensity, run.status.value,
                 run.created_at, tenant_id),
            )

    def set_status(self, run_id: str, status: str) -> None:
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE runs SET status = %s, updated_at = now() WHERE id = %s", (status, run_id)
            )

    def get(self, run_id: str) -> Optional[Run]:
        """One run as a typed model (a `RunRow`, i.e. a `Run` carrying `updated_at`), so this and the
        API's in-memory fallback answer with the same shape. Returns None when the run is unknown."""
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT id, engagement_id, target, status, created_at, updated_at "
                "FROM runs WHERE id = %s",
                (run_id,),
            ).fetchone()
        if not row:
            return None
        return RunRow(
            id=row[0], engagement_id=row[1], target=row[2], status=row[3],
            created_at=row[4], updated_at=row[5],
        )


_FINDING_COLS = [
    "dedup_key", "id", "engagement_id", "run_id", "title", "category", "severity", "state",
    "confidence", "target", "cwe", "cve", "cvss_score", "cvss_vector", "attack_technique",
    "attack_technique_name", "evidence", "source_tool", "first_seen", "last_seen", "times_seen",
]


# One statement for both the singular and the batched write path, so their semantics can never
# drift. On re-observation we bump last_seen/times_seen, keep the highest confidence seen, and
# refresh the descriptive fields — but the triage state only ever moves forward:
#   * false_positive is sticky (a human decided it),
#   * confirmed is never demoted back to suspected.
# Every normalizer builds findings with the Finding default state 'suspected', so copying
# EXCLUDED.state across unconditionally silently undid /validate on the next re-observation (and,
# through NetworkMemory._is_exploitable_finding, un-flagged target devices in the network map).
_UPSERT_FINDING_SQL = """
    INSERT INTO findings
        (dedup_key, id, engagement_id, run_id, title, category, severity, state,
         confidence, target, cwe, cve, cvss_score, cvss_vector, attack_technique,
         attack_technique_name, evidence, source_tool, tenant_id)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (dedup_key) DO UPDATE SET
        last_seen = now(),
        times_seen = findings.times_seen + 1,
        run_id = EXCLUDED.run_id,
        state = CASE
                    WHEN findings.state = 'false_positive' THEN 'false_positive'
                    WHEN findings.state = 'confirmed' THEN 'confirmed'
                    ELSE EXCLUDED.state
                END,
        confidence = GREATEST(findings.confidence, EXCLUDED.confidence),
        severity = EXCLUDED.severity,
        title = EXCLUDED.title,
        evidence = EXCLUDED.evidence,
        -- severity/cvss follow the newest observation together: enrich_finding recomputes
        -- cvss_score from (vector, severity) on every observation, so pinning the score while
        -- refreshing severity would leave the two disagreeing. The vector and cwe are only ever
        -- *added*, never cleared — a tool that reports the same issue without a vector or a CWE
        -- mapping should not erase the richer classification an earlier tool supplied.
        cvss_score = EXCLUDED.cvss_score,
        cvss_vector = COALESCE(EXCLUDED.cvss_vector, findings.cvss_vector),
        cwe = COALESCE(EXCLUDED.cwe, findings.cwe),
        -- cve participates in dedup_key (models.Finding.dedup_key joins engagement, category,
        -- normalized target and `cve or ''`), so a row that conflicts here necessarily carried the
        -- same CVE — or one side is NULL and the other '', the two spellings of "no CVE". A plain
        -- EXCLUDED.cve is therefore never a real update, but it *can* undo an analyst who filled the
        -- column in by hand without recomputing dedup_key. COALESCE keeps the fill-in-if-missing
        -- behaviour and gives up nothing, since an existing CVE can never be the wrong one.
        cve = COALESCE(findings.cve, EXCLUDED.cve)
"""


def _finding_params(f: Finding, tenant_id: str) -> tuple:
    return (
        f.dedup_key(), f.id, f.engagement_id, f.run_id, f.title, f.category,
        f.severity.value, f.state.value, f.confidence, f.target, f.cwe, f.cve,
        f.cvss_score, f.cvss_vector, f.attack_technique, f.attack_technique_name,
        f.evidence, f.source_tool, tenant_id,
    )


def _row_to_finding(r: dict) -> Finding:
    return Finding(
        id=r["id"], engagement_id=r["engagement_id"], run_id=r["run_id"], title=r["title"],
        category=r["category"], severity=r["severity"], state=r["state"],
        confidence=r["confidence"], target=r["target"], cwe=r["cwe"], cve=r["cve"],
        cvss_score=r["cvss_score"], cvss_vector=r["cvss_vector"],
        attack_technique=r["attack_technique"], attack_technique_name=r["attack_technique_name"],
        evidence=r["evidence"] or "", source_tool=r["source_tool"] or "",
    )


class FindingRepo:
    def __init__(self, db: Database):
        self._db = db

    def upsert(self, f: Finding, tenant_id: str = "default") -> None:
        with self._db.connection() as conn:
            conn.execute(_UPSERT_FINDING_SQL, _finding_params(f, tenant_id))

    def upsert_many(self, findings: Sequence[Finding], tenant_id: str = "default") -> int:
        """Batched form of `upsert`: one borrowed connection and one executemany for the whole
        step, instead of a connection round trip per finding. Returns the number of rows sent.

        Semantics are identical to calling `upsert` in a loop, including the times_seen bump when
        the same dedup_key appears twice in one batch (each row is its own statement)."""
        rows = [_finding_params(f, tenant_id) for f in findings or ()]
        if not rows:
            return 0
        with self._db.connection() as conn:
            with conn.cursor() as cur:
                cur.executemany(_UPSERT_FINDING_SQL, rows)
        return len(rows)

    def query(self, engagement_id: str, filters: FindingFilters,
              tenant_id: Optional[str] = None) -> list[dict]:
        sql, params = build_findings_query(engagement_id, filters, tenant_id)
        with self._db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(zip(_FINDING_COLS, r)) for r in rows]

    def count(self, engagement_id: str, tenant_id: Optional[str] = None) -> int:
        """Total findings for an engagement. Callers compare this against len(list_findings(...))
        to tell a complete result from a truncated one."""
        clauses, params = ["engagement_id = %s"], [engagement_id]
        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT count(*) FROM findings WHERE " + " AND ".join(clauses), params
            ).fetchone()
        return int(row[0]) if row else 0

    def iter_findings(self, engagement_id: str, page: int = LIST_PAGE_SIZE,
                      tenant_id: Optional[str] = None,
                      max_rows: int = MAX_LIST_FINDINGS) -> Iterator[Finding]:
        """Yield every finding of an engagement, paging past the per-query clamp of
        build_findings_query so aggregate readers (/report, /chains) see the whole set.

        Stops after `max_rows` (see MAX_LIST_FINDINGS) so an enormous engagement degrades to a capped
        answer rather than exhausting memory. build_findings_query's ORDER BY ends in dedup_key — the
        primary key — which makes the sort a total order; without that tiebreaker two rows sharing a
        (cvss_score, last_seen) could swap between pages and this walk would skip or repeat them.
        """
        page = max(1, min(int(page), LIST_PAGE_SIZE))
        max_rows = max(1, int(max_rows))
        offset = yielded = 0
        while yielded < max_rows:
            want = min(page, max_rows - yielded)
            rows = self.query(
                engagement_id, FindingFilters(limit=want, offset=offset), tenant_id)
            if not rows:
                return
            for r in rows:
                yield _row_to_finding(r)
            yielded += len(rows)
            # Advance by rows actually seen, not by `want`, so a short page can never skip a row.
            offset += len(rows)
            if len(rows) < want:
                return

    def list_findings(self, engagement_id: str, all: bool = False,
                      tenant_id: Optional[str] = None) -> list[Finding]:
        """Return findings as domain objects (for correlation and reporting).

        By default this is the historical single-query behaviour, capped at LIST_PAGE_SIZE — a
        result of exactly that length may be truncated (compare with `count`). Pass `all=True` to
        page through the complete set.
        """
        if all:
            return list(self.iter_findings(engagement_id, tenant_id=tenant_id))
        rows = self.query(engagement_id, FindingFilters(limit=LIST_PAGE_SIZE), tenant_id)
        return [_row_to_finding(r) for r in rows]

    def promote_corroborated(self, engagement_id: str) -> int:
        """Confirm suspected findings seen in more than one run with high enough confidence.
        Mirrors app.validation.should_confirm as a single set-based UPDATE."""
        from .validation import CONFIRM_MIN_CONFIDENCE

        with self._db.connection() as conn:
            cur = conn.execute(
                "UPDATE findings SET state = 'confirmed' "
                "WHERE engagement_id = %s AND state = 'suspected' "
                "AND times_seen >= 2 AND confidence >= %s",
                (engagement_id, CONFIRM_MIN_CONFIDENCE),
            )
            return cur.rowcount


_UPSERT_SERVICE_SQL = """
    INSERT INTO services (engagement_id, address, port, proto, service, product, tenant_id)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (engagement_id, address, port, proto) DO UPDATE SET
        last_seen = now(), service = EXCLUDED.service, product = EXCLUDED.product
"""


class ServiceRepo:
    def __init__(self, db: Database):
        self._db = db

    def upsert(self, engagement_id: str, address: str, port: int, proto: str,
               service: str = "", product: str = "", tenant_id: str = "default") -> None:
        with self._db.connection() as conn:
            conn.execute(
                _UPSERT_SERVICE_SQL,
                (engagement_id, address, port, proto, service, product, tenant_id),
            )

    def upsert_many(self, engagement_id: str, rows: Iterable[Sequence],
                    tenant_id: str = "default") -> int:
        """Batched form of `upsert`. `rows` is a sequence of
        (address, port, proto, service, product) tuples — one borrowed connection and one
        executemany for the whole step. Returns the number of rows sent."""
        params = [
            (engagement_id, r[0], r[1], r[2],
             r[3] if len(r) > 3 else "", r[4] if len(r) > 4 else "", tenant_id)
            for r in rows or ()
        ]
        if not params:
            return 0
        with self._db.connection() as conn:
            with conn.cursor() as cur:
                cur.executemany(_UPSERT_SERVICE_SQL, params)
        return len(params)

    def search(self, engagement_id: str, q: str, limit: int = 100) -> list[dict]:
        # Entity lookup for the Maltego-style map: match hosts/services by substring.
        like = f"%{q}%"
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT address, port, proto, service, product FROM services "
                "WHERE engagement_id = %s AND (address ILIKE %s OR service ILIKE %s OR product ILIKE %s) "
                "ORDER BY address, port LIMIT %s",
                (engagement_id, like, like, like, min(limit, 500)),
            ).fetchall()
        cols = ["address", "port", "proto", "service", "product"]
        return [dict(zip(cols, r)) for r in rows]


class MetricsRepo:
    def __init__(self, db: Database):
        self._db = db

    def kpis(self, engagement_id: str) -> dict:
        """Aggregate every dashboard number in two round trips.

        The first query folds the three scalar counts (which live on two different tables) into one
        row of subqueries; the second uses FILTER aggregates plus ROLLUP so the per-severity
        breakdown and the whole-engagement totals come back together. The extra ROLLUP row is the
        one with severity IS NULL.
        """
        with self._db.connection() as conn:
            counts = conn.execute(
                "SELECT (SELECT count(DISTINCT address) FROM services WHERE engagement_id = %s), "
                "       (SELECT count(*) FROM services WHERE engagement_id = %s), "
                "       (SELECT count(*) FROM runs WHERE engagement_id = %s)",
                (engagement_id, engagement_id, engagement_id),
            ).fetchone()
            finding_rows = conn.execute(
                "SELECT severity, count(*) AS n, "
                "       count(*) FILTER (WHERE state <> 'false_positive') AS open_issues, "
                "       count(DISTINCT cve) AS cves "
                "FROM findings WHERE engagement_id = %s GROUP BY ROLLUP (severity)",
                (engagement_id,),
            ).fetchall()

        hosts, exposed, runs = (counts or (0, 0, 0))
        by_sev: dict[str, int] = {}
        open_issues = cves = 0
        for severity, n, open_n, cve_n in finding_rows:
            if severity is None:  # the ROLLUP total row
                open_issues, cves = open_n, cve_n
            else:
                by_sev[severity] = n
        return {
            "hosts": hosts,
            "exposed_endpoints": exposed,
            "cves_identified": cves,
            "open_issues": open_issues,
            "findings_by_severity": by_sev,
            "runs": runs,
        }


class PersistenceSink:
    """Write interface the orchestrator uses during a run. Bundles the repos it needs so the
    orchestrator stays agnostic about storage."""

    def __init__(self, db: Database):
        self._runs = RunRepo(db)
        self._findings = FindingRepo(db)
        self._services = ServiceRepo(db)

    def for_tenant(self, tenant_id: str) -> "TenantScopedSink":
        """A view of this sink that stamps every row it writes with `tenant_id` (C11).

        A run is owned by exactly one tenant for its whole lifetime, so the tenant belongs to the
        *sink handed to the run*, not to each call. Binding it here keeps `execute_tool_step` free of
        a tenant argument it would only ever forward — the orchestrator's stated contract is that it
        knows nothing about storage, and "which tenant owns this row" is a storage concern.
        """
        return TenantScopedSink(self, tenant_id)

    def set_run_status(self, run_id: str, status: str) -> None:
        self._runs.set_status(run_id, status)

    def record_finding(self, finding: Finding, tenant_id: str = "default") -> None:
        self._findings.upsert(finding, tenant_id)

    def record_findings(self, findings: Sequence[Finding], tenant_id: str = "default") -> int:
        """Batched `record_finding` — one round trip for a whole tool step."""
        return self._findings.upsert_many(findings, tenant_id)

    def upsert_service(self, engagement_id: str, address: str, port: int, proto: str,
                       service: str = "", product: str = "", tenant_id: str = "default") -> None:
        self._services.upsert(engagement_id, address, port, proto, service, product, tenant_id)

    def upsert_services(self, engagement_id: str, rows: Iterable[Sequence],
                        tenant_id: str = "default") -> int:
        """Batched `upsert_service`. `rows` is a sequence of
        (address, port, proto, service, product) tuples."""
        return self._services.upsert_many(engagement_id, rows, tenant_id)


class TenantScopedSink:
    """A `PersistenceSink` bound to one tenant, handed to a run in place of the process-wide sink.

    The method surface is deliberately identical to `PersistenceSink`'s — same names, same positional
    arguments — and written out explicitly rather than proxied through `__getattr__`, because
    `execute_tool_step` feature-detects the batched writers with `hasattr(db, "upsert_services")` /
    `hasattr(db, "record_findings")`. A catch-all proxy would answer `hasattr` for *every* name and
    turn that detection into a lie; this class answers it truthfully.

    `tenant_id` stays an accepted keyword on each method so the view remains substitutable for the
    unbound sink, but an explicit value is ignored: a run cannot write outside the tenant it was
    launched for, whatever a caller passes down.
    """

    def __init__(self, sink: PersistenceSink, tenant_id: str):
        self._sink = sink
        self.tenant_id = tenant_id or "default"

    def for_tenant(self, tenant_id: str) -> "TenantScopedSink":
        # Rebinding goes back to the underlying sink, so views never nest.
        return TenantScopedSink(self._sink, tenant_id)

    def set_run_status(self, run_id: str, status: str) -> None:
        self._sink.set_run_status(run_id, status)

    def record_finding(self, finding: Finding, tenant_id: Optional[str] = None) -> None:
        self._sink.record_finding(finding, self.tenant_id)

    def record_findings(self, findings: Sequence[Finding],
                        tenant_id: Optional[str] = None) -> int:
        return self._sink.record_findings(findings, self.tenant_id)

    def upsert_service(self, engagement_id: str, address: str, port: int, proto: str,
                       service: str = "", product: str = "",
                       tenant_id: Optional[str] = None) -> None:
        self._sink.upsert_service(engagement_id, address, port, proto, service, product,
                                  self.tenant_id)

    def upsert_services(self, engagement_id: str, rows: Iterable[Sequence],
                        tenant_id: Optional[str] = None) -> int:
        return self._sink.upsert_services(engagement_id, rows, self.tenant_id)
