"""Local CVE database access.

`lookup` is what the agent's cve_lookup tool calls to turn a discovered product (and optional
version) into known CVEs, entirely offline. `seed` bulk-loads records from a data file or NVD export.
Matching is deliberately loose (product substring, optional version substring) — an assessment tool
should over-surface candidate CVEs for the analyst/agent to confirm, not silently miss them.
"""
from __future__ import annotations

from dataclasses import dataclass

from .db.database import Database


@dataclass
class CveRecord:
    cve_id: str
    product: str
    version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cwe: str | None
    description: str | None


class CveRepo:
    def __init__(self, db: Database):
        self._db = db

    def seed(self, records: list[dict]) -> int:
        # One executemany for the whole file: an NVD export is tens of thousands of rows, and a
        # round trip per row makes seeding the dominant cost of a cold start.
        rows = [
            (r["cve_id"], r["product"], r.get("version"), r.get("cvss_score"),
             r.get("cvss_vector"), r.get("cwe"), r.get("description"), r.get("published"))
            for r in records or []
        ]
        if not rows:
            return 0
        with self._db.connection() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO cves (cve_id, product, version, cvss_score, cvss_vector, cwe, description, published)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        product = EXCLUDED.product, version = EXCLUDED.version,
                        cvss_score = EXCLUDED.cvss_score, cvss_vector = EXCLUDED.cvss_vector,
                        cwe = EXCLUDED.cwe, description = EXCLUDED.description
                    """,
                    rows,
                )
        return len(rows)

    def lookup(self, product: str, version: str | None = None, limit: int = 25) -> list[CveRecord]:
        clauses = ["lower(product) LIKE %s"]
        params: list = [f"%{product.lower()}%"]
        if version:
            # Match rows whose affected-version text contains the queried version, or that apply to
            # all versions (NULL/empty).
            clauses.append("(version IS NULL OR version = '' OR version LIKE %s)")
            params.append(f"%{version}%")
        params.append(min(limit, 100))
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT cve_id, product, version, cvss_score, cvss_vector, cwe, description "
                "FROM cves WHERE " + " AND ".join(clauses) +
                " ORDER BY cvss_score DESC NULLS LAST LIMIT %s",
                params,
            ).fetchall()
        return [CveRecord(*r) for r in rows]
