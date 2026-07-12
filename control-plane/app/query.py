"""Query tooling: a parameterized filter builder for findings, and a read-only Cypher guard.

Both are pure functions so they can be unit-tested without a database. The finding builder only
ever emits parameter placeholders (never string-interpolated values) so it is injection-safe. The
Cypher guard is the first of two layers protecting the graph query endpoint; the second is running
the query inside a Neo4j READ transaction, which the server itself refuses to let write.
"""
from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel


class FindingFilters(BaseModel):
    severity: Optional[str] = None
    category: Optional[str] = None
    state: Optional[str] = None
    cve: Optional[str] = None
    target: Optional[str] = None
    q: Optional[str] = None  # free-text match against title/evidence
    limit: int = 200


def build_findings_query(engagement_id: str, f: FindingFilters, tenant_id: str | None = None) -> tuple[str, list]:
    """Return (sql, params). Every user value is a bound parameter, never interpolated.

    When `tenant_id` is given, results are additionally scoped to that tenant so one tenant can never
    read another's findings even if it guesses an engagement id.
    """
    clauses = ["engagement_id = %s"]
    params: list = [engagement_id]

    if tenant_id is not None:
        clauses.append("tenant_id = %s")
        params.append(tenant_id)

    for column, value in (
        ("severity", f.severity),
        ("category", f.category),
        ("state", f.state),
        ("cve", f.cve),
        ("target", f.target),
    ):
        if value:
            clauses.append(f"{column} = %s")
            params.append(value)

    if f.q:
        clauses.append("(title ILIKE %s OR evidence ILIKE %s)")
        like = f"%{f.q}%"
        params.extend([like, like])

    limit = max(1, min(f.limit, 1000))  # clamp so a query can't pull the whole table
    sql = (
        "SELECT dedup_key, id, engagement_id, run_id, title, category, severity, state, "
        "confidence, target, cwe, cve, cvss_score, cvss_vector, attack_technique, "
        "attack_technique_name, evidence, source_tool, first_seen, last_seen, times_seen "
        "FROM findings WHERE " + " AND ".join(clauses) +
        " ORDER BY cvss_score DESC, last_seen DESC LIMIT %s"
    )
    params.append(limit)
    return sql, params


# Clauses that mutate the graph or the database. Any of these fails the guard outright.
_FORBIDDEN = re.compile(
    r"\b(create|merge|delete|detach|set|remove|drop|foreach|load\s+csv)\b", re.IGNORECASE
)


def is_read_only_cypher(cypher: str) -> tuple[bool, str]:
    """Reject anything that could write or smuggle a second statement. Deny by default."""
    text = cypher.strip()
    if not text:
        return False, "empty query"
    if ";" in text.rstrip(";"):
        return False, "multiple statements are not allowed"
    if "//" in text or "/*" in text:
        return False, "comments are not allowed"
    match = _FORBIDDEN.search(text)
    if match:
        return False, f"write clause '{match.group(1)}' is not allowed"
    return True, "ok"
