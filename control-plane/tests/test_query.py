"""Tests for the query tooling that needs no database: filter builder + read-only Cypher guard."""
from app.query import FindingFilters, build_findings_query, is_read_only_cypher


def test_filter_builder_binds_every_value():
    f = FindingFilters(severity="high", cve="CVE-2024-1", q="ssh", limit=50)
    sql, params = build_findings_query("e1", f)
    # engagement + severity + cve + two ILIKE for q + limit -> 6 bound params, no interpolation.
    assert params == ["e1", "high", "CVE-2024-1", "%ssh%", "%ssh%", 50]
    assert sql.count("%s") == len(params)
    assert "ORDER BY cvss_score DESC, last_seen DESC" in sql


def test_filter_builder_clamps_limit():
    _, params = build_findings_query("e1", FindingFilters(limit=99999))
    assert params[-1] == 1000  # clamped ceiling
    _, params = build_findings_query("e1", FindingFilters(limit=0))
    assert params[-1] == 1


def test_cypher_guard_allows_read():
    ok, _ = is_read_only_cypher("MATCH (n:IP) RETURN n LIMIT 10")
    assert ok


def test_cypher_guard_blocks_writes():
    for q in [
        "MATCH (n) DETACH DELETE n",
        "CREATE (x:Evil)",
        "MATCH (n:IP) SET n.owned = true RETURN n",
        "MERGE (a:IP {address:'1.2.3.4'})",
        "MATCH (n) RETURN n; DROP DATABASE neo4j",
        "MATCH (n) RETURN n // sneaky\nDELETE n",
    ]:
        ok, reason = is_read_only_cypher(q)
        assert not ok, f"should have blocked: {q}"
        assert reason
