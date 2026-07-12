"""Repositories over Postgres: durable reads/writes for engagements, runs, findings, services,
plus KPI aggregation and entity search that power the dashboard and query UI.

All SQL uses bound parameters. The PersistenceSink at the bottom is the write interface the
orchestrator calls during a run.
"""
from __future__ import annotations

import json
from typing import Optional

from .db.database import Database
from .models import Engagement, Finding, Run, Scope
from .query import FindingFilters, build_findings_query


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

    def get(self, engagement_id: str) -> Optional[Engagement]:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT id, name, scope, created_at FROM engagements WHERE id = %s",
                (engagement_id,),
            ).fetchone()
        if not row:
            return None
        return Engagement(id=row[0], name=row[1], scope=Scope(**row[2]), created_at=row[3])

    def list(self) -> list[Engagement]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT id, name, scope, created_at FROM engagements ORDER BY created_at DESC"
            ).fetchall()
        return [Engagement(id=r[0], name=r[1], scope=Scope(**r[2]), created_at=r[3]) for r in rows]


class RunRepo:
    def __init__(self, db: Database):
        self._db = db

    def save(self, run: Run) -> None:
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO runs (id, engagement_id, target, status, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, now()) "
                "ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = now()",
                (run.id, run.engagement_id, run.target, run.status.value, run.created_at),
            )

    def set_status(self, run_id: str, status: str) -> None:
        with self._db.connection() as conn:
            conn.execute(
                "UPDATE runs SET status = %s, updated_at = now() WHERE id = %s", (status, run_id)
            )

    def get(self, run_id: str) -> Optional[dict]:
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT id, engagement_id, target, status, created_at, updated_at "
                "FROM runs WHERE id = %s",
                (run_id,),
            ).fetchone()
        if not row:
            return None
        cols = ["id", "engagement_id", "target", "status", "created_at", "updated_at"]
        return dict(zip(cols, row))


_FINDING_COLS = [
    "dedup_key", "id", "engagement_id", "run_id", "title", "category", "severity", "state",
    "confidence", "target", "cwe", "cve", "cvss_score", "cvss_vector", "attack_technique",
    "attack_technique_name", "evidence", "source_tool", "first_seen", "last_seen", "times_seen",
]


class FindingRepo:
    def __init__(self, db: Database):
        self._db = db

    def upsert(self, f: Finding) -> None:
        # On re-observation, bump last_seen/times_seen and keep the highest confidence seen.
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO findings
                    (dedup_key, id, engagement_id, run_id, title, category, severity, state,
                     confidence, target, cwe, cve, cvss_score, cvss_vector, attack_technique,
                     attack_technique_name, evidence, source_tool)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (dedup_key) DO UPDATE SET
                    last_seen = now(),
                    times_seen = findings.times_seen + 1,
                    run_id = EXCLUDED.run_id,
                    state = EXCLUDED.state,
                    confidence = GREATEST(findings.confidence, EXCLUDED.confidence),
                    cvss_score = EXCLUDED.cvss_score
                """,
                (
                    f.dedup_key(), f.id, f.engagement_id, f.run_id, f.title, f.category,
                    f.severity.value, f.state.value, f.confidence, f.target, f.cwe, f.cve,
                    f.cvss_score, f.cvss_vector, f.attack_technique, f.attack_technique_name,
                    f.evidence, f.source_tool,
                ),
            )

    def query(self, engagement_id: str, filters: FindingFilters) -> list[dict]:
        sql, params = build_findings_query(engagement_id, filters)
        with self._db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(zip(_FINDING_COLS, r)) for r in rows]

    def list_findings(self, engagement_id: str) -> list[Finding]:
        """Return findings as domain objects (for correlation and reporting)."""
        rows = self.query(engagement_id, FindingFilters(limit=1000))
        return [
            Finding(
                id=r["id"], engagement_id=r["engagement_id"], run_id=r["run_id"], title=r["title"],
                category=r["category"], severity=r["severity"], state=r["state"],
                confidence=r["confidence"], target=r["target"], cwe=r["cwe"], cve=r["cve"],
                cvss_score=r["cvss_score"], cvss_vector=r["cvss_vector"],
                attack_technique=r["attack_technique"], attack_technique_name=r["attack_technique_name"],
                evidence=r["evidence"] or "", source_tool=r["source_tool"] or "",
            )
            for r in rows
        ]

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


class ServiceRepo:
    def __init__(self, db: Database):
        self._db = db

    def upsert(self, engagement_id: str, address: str, port: int, proto: str,
               service: str = "", product: str = "") -> None:
        with self._db.connection() as conn:
            conn.execute(
                """
                INSERT INTO services (engagement_id, address, port, proto, service, product)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (engagement_id, address, port, proto) DO UPDATE SET
                    last_seen = now(), service = EXCLUDED.service, product = EXCLUDED.product
                """,
                (engagement_id, address, port, proto, service, product),
            )

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
        """Aggregate the dashboard numbers in one round trip per metric group."""
        with self._db.connection() as conn:
            hosts = conn.execute(
                "SELECT count(DISTINCT address) FROM services WHERE engagement_id = %s",
                (engagement_id,),
            ).fetchone()[0]
            exposed = conn.execute(
                "SELECT count(*) FROM services WHERE engagement_id = %s", (engagement_id,)
            ).fetchone()[0]
            cves = conn.execute(
                "SELECT count(DISTINCT cve) FROM findings WHERE engagement_id = %s AND cve IS NOT NULL",
                (engagement_id,),
            ).fetchone()[0]
            open_issues = conn.execute(
                "SELECT count(*) FROM findings WHERE engagement_id = %s AND state <> 'false_positive'",
                (engagement_id,),
            ).fetchone()[0]
            by_sev = conn.execute(
                "SELECT severity, count(*) FROM findings WHERE engagement_id = %s GROUP BY severity",
                (engagement_id,),
            ).fetchall()
            runs = conn.execute(
                "SELECT count(*) FROM runs WHERE engagement_id = %s", (engagement_id,)
            ).fetchone()[0]
        return {
            "hosts": hosts,
            "exposed_endpoints": exposed,
            "cves_identified": cves,
            "open_issues": open_issues,
            "findings_by_severity": {sev: cnt for sev, cnt in by_sev},
            "runs": runs,
        }


class PersistenceSink:
    """Write interface the orchestrator uses during a run. Bundles the repos it needs so the
    orchestrator stays agnostic about storage."""

    def __init__(self, db: Database):
        self._runs = RunRepo(db)
        self._findings = FindingRepo(db)
        self._services = ServiceRepo(db)

    def set_run_status(self, run_id: str, status: str) -> None:
        self._runs.set_status(run_id, status)

    def record_finding(self, finding: Finding) -> None:
        self._findings.upsert(finding)

    def upsert_service(self, engagement_id: str, address: str, port: int, proto: str,
                       service: str = "", product: str = "") -> None:
        self._services.upsert(engagement_id, address, port, proto, service, product)
