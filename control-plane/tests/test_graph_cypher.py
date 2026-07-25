"""Graph-layer tests: the Cypher `GraphClient` emits, and schema.cypher's agreement with it.

There is no Neo4j in the test environment, so these tests drive the client through a fake driver and
assert on the *text* of the queries and the parameters bound to them. That is deliberately narrow —
it cannot prove a query runs — but it does pin the two properties that are expensive to get wrong:

  1. The batched writers (`upsert_services`, `record_findings`) must write byte-identical MERGE keys
     and first_seen/last_seen/first_run_id/last_run_id bookkeeping to their singular counterparts.
     The cross-run memory engine diffs the map off exactly those timestamps, so any drift between
     the two paths silently breaks change detection instead of failing loudly.
  2. Every label `get_graph` scans must have a matching engagement_id index in schema.cypher, or that
     branch quietly degrades to a label scan.
"""
import re
import uuid
from pathlib import Path

import pytest

from app.correlation import correlate
from app.graph import GRAPH_LABELS, GraphClient
from app.models import AttackChain, Finding, Severity

SCHEMA = Path(__file__).resolve().parents[2] / "graph" / "schema.cypher"


# --- fake driver -----------------------------------------------------------------------------------


class _FakeResult(list):
    def consume(self):
        return None


class _FakeTx:
    def __init__(self, calls):
        self._calls = calls

    def run(self, query, **params):
        self._calls.append((query, params))
        return _FakeResult()


class _FakeSession:
    def __init__(self, calls, records):
        self._calls, self._records = calls, records

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self._calls.append((query, params))
        return _FakeResult(self._records)

    def execute_write(self, fn):
        return fn(_FakeTx(self._calls))

    def execute_read(self, fn):
        return fn(_FakeTx(self._calls))


class _FakeDriver:
    def __init__(self, records):
        self.calls, self.sessions, self._records = [], 0, records

    def session(self, **kwargs):
        self.sessions += 1
        self.last_session_kwargs = kwargs
        return _FakeSession(self.calls, self._records)


class _Node:
    """Stands in for neo4j.graph.Node: element_id, labels, and mapping access for dict(node)."""

    def __init__(self, element_id, label, **props):
        self.element_id, self.labels, self._props = element_id, {label}, props

    def keys(self):
        return self._props.keys()

    def __getitem__(self, key):
        return self._props[key]


class _Rel:
    def __init__(self, element_id, start, end, type_):
        self.element_id, self.start_node, self.end_node, self.type = element_id, start, end, type_


def client(records=()):
    """A GraphClient bound to a fake driver — no server, and the exact Cypher is readable back."""
    c = GraphClient.__new__(GraphClient)  # bypass __init__ so no real driver is constructed
    c._driver = _FakeDriver(list(records))
    return c


def _norm(query: str) -> str:
    return " ".join(query.split())


def mk_finding(target="10.0.0.5", severity=Severity.high, cwe=None, category="open-port"):
    return Finding(
        id=str(uuid.uuid4()), engagement_id="e1", run_id="r1", title=f"t {target}",
        category=category, severity=severity, target=target, cwe=cwe, source_tool="nmap",
    )


# --- B2: the batched writers must not drift from the singular ones ----------------------------------


def test_batched_topology_is_identical_to_the_singular_bookkeeping():
    """upsert_services must differ from upsert_service *only* by the UNWIND preamble and row.* refs.

    Anything else — a reordered clause, a dropped ON MATCH, a renamed property — would mean the two
    write paths date nodes differently, and the memory engine's diff would depend on which one ran.
    """
    single = client()
    single.upsert_service("e1", "10.0.0.5", 80, "tcp", "http", "nginx", "r1")
    batch = client()
    batch.upsert_services(
        "e1",
        [{"address": "10.0.0.5", "port": 80, "proto": "tcp", "service": "http", "product": "nginx"}],
        run_id="r1",
    )
    rewritten = _norm(batch._driver.calls[0][0]).replace("WITH e UNWIND $rows AS row ", "")
    for field in ("addr", "port", "proto", "service", "product"):
        rewritten = rewritten.replace(f"row.{field}", f"${field}")
    assert rewritten == _norm(single._driver.calls[0][0])


def test_batched_topology_binds_the_same_values_as_the_singular_call():
    single = client()
    single.upsert_service("e1", "10.0.0.5", 80, "tcp", "http", "nginx", "r1")
    batch = client()
    batch.upsert_services(
        "e1",
        [{"address": "10.0.0.5", "port": 80, "proto": "tcp", "service": "http", "product": "nginx"}],
        run_id="r1",
    )
    single_params = single._driver.calls[0][1]
    batch_params = batch._driver.calls[0][1]
    assert batch_params["eid"] == single_params["eid"] == "e1"
    assert batch_params["rid"] == single_params["rid"] == "r1"
    assert batch_params["rows"] == [
        {"addr": "10.0.0.5", "port": 80, "proto": "tcp", "service": "http", "product": "nginx"}
    ]


@pytest.mark.parametrize("target", ["https://app.example.com/q", "10.0.0.5"])
def test_batched_finding_writes_are_identical_to_the_singular_ones(target):
    """Both branches of the target split (Endpoint for URLs, IP otherwise) must match record_finding."""
    finding = mk_finding(target)
    single = client()
    single.record_finding(finding)
    batch = client()
    batch.record_findings([finding])
    rewritten = _norm(batch._driver.calls[0][0]).replace("UNWIND $rows AS row ", "")
    for field in (
        "dedup", "id", "eid", "rid", "title", "category", "severity", "state", "confidence",
        "target", "cwe", "cve", "cvss", "vector", "tech_name", "tech", "evidence", "tool", "created",
    ):
        rewritten = rewritten.replace(f"row.{field}", f"${field}")
    assert rewritten == _norm(single._driver.calls[0][0])


def test_record_findings_splits_by_target_type_and_costs_one_trip_per_kind():
    findings = [
        mk_finding("10.0.0.5"), mk_finding("10.0.0.9"),
        mk_finding("https://a/b"), mk_finding("http://a/c"),
    ]
    c = client()
    c.record_findings(findings)
    assert len(c._driver.calls) == 2, "one round trip per target kind, not per finding"
    queries = [q for q, _ in c._driver.calls]
    url_query = next(q for q in queries if "Endpoint" in q)
    host_query = next(q for q in queries if "t:IP" in q)
    assert "t:IP" not in url_query and "Endpoint" not in host_query
    assert len(dict(c._driver.calls)[url_query]["rows"]) == 2
    assert len(dict(c._driver.calls)[host_query]["rows"]) == 2


def test_batch_writers_are_no_ops_on_an_empty_list():
    """The runtime calls these unconditionally per tool step; an empty step must not open a session."""
    for call in (
        lambda c: c.upsert_services("e1", []),
        lambda c: c.upsert_services("e1", None),
        lambda c: c.record_findings([]),
        lambda c: c.record_findings(None),
    ):
        c = client()
        call(c)
        assert c._driver.sessions == 0 and c._driver.calls == []


def test_upsert_services_accepts_plain_dicts_and_attribute_objects_alike():
    """The published contract is plain dicts (graph.py cannot import runtime's ServiceObservation),
    but orchestrator._persist_services passes the dataclass straight through. Both must work."""
    class Obs:
        address, port, proto, service, product = "10.0.0.5", 80, "tcp", "http", "nginx"

    from_dict = client()
    from_dict.upsert_services(
        "e1",
        [{"address": "10.0.0.5", "port": 80, "proto": "tcp", "service": "http", "product": "nginx"}],
    )
    from_obj = client()
    from_obj.upsert_services("e1", [Obs()])
    assert from_dict._driver.calls[0][1]["rows"] == from_obj._driver.calls[0][1]["rows"]


def test_upsert_services_defaults_match_the_singular_signature():
    c = client()
    c.upsert_services("e1", [{"address": "10.0.0.5", "port": 80}])
    assert c._driver.calls[0][1]["rows"] == [
        {"addr": "10.0.0.5", "port": 80, "proto": "tcp", "service": "", "product": ""}
    ]


def test_upsert_services_collapses_repeated_merge_keys_keeping_the_last():
    """Two sequential upsert_service calls for one (address, port) leave the second call's
    name/product on the node; the batch must land on the same state rather than relying on the
    planner making repeated UNWIND rows converge."""
    c = client()
    c.upsert_services("e1", [
        {"address": "10.0.0.5", "port": 80, "proto": "tcp", "service": "http", "product": "nginx"},
        {"address": "10.0.0.5", "port": 80, "proto": "tcp", "service": "http", "product": "apache"},
        {"address": "10.0.0.5", "port": 443, "proto": "tcp"},
    ])
    rows = c._driver.calls[0][1]["rows"]
    assert len(rows) == 2
    assert next(r for r in rows if r["port"] == 80)["product"] == "apache"


def test_record_findings_collapses_repeated_dedup_keys_keeping_the_last():
    first, second = mk_finding("10.0.0.5"), mk_finding("10.0.0.5")
    assert first.dedup_key() == second.dedup_key(), "same target/category/tool -> same dedup key"
    c = client()
    c.record_findings([first, second])
    rows = c._driver.calls[0][1]["rows"]
    assert len(rows) == 1 and rows[0]["id"] == second.id


def test_upsert_services_requires_the_merge_key():
    """address/port are two thirds of the Service MERGE key; a missing one must fail loudly rather
    than MERGE a node keyed on null."""
    c = client()
    with pytest.raises(KeyError):
        c.upsert_services("e1", [{"port": 80}])


# --- B5: get_graph must scan by label and limit nodes, not rows -------------------------------------


def test_get_graph_per_engagement_uses_only_labelled_scans():
    c = client()
    c.get_graph("e1", limit=10)
    query, params = c._driver.calls[0]
    assert "MATCH (n {" not in query, "an unlabelled property match cannot use any index"
    for label in GRAPH_LABELS:
        assert f"MATCH (n:{label} {{engagement_id: $eid}})" in query
    assert params["eid"] == "e1"


def test_get_graph_cross_engagement_uses_only_labelled_scans():
    c = client()
    c.get_graph(None, limit=10)
    query, _ = c._driver.calls[0]
    assert not re.search(r"MATCH \(n\)(?!-)", query), "a bare MATCH (n) plans an AllNodesScan"
    for label in GRAPH_LABELS:
        assert f"MATCH (n:{label})" in query


def test_get_graph_limits_nodes_before_expanding_relationships():
    """Applying LIMIT to rows let one hub node's relationships crowd every other node out of the
    payload, so the map rendered wrong rather than merely truncated."""
    for engagement_id in ("e1", None):
        c = client()
        c.get_graph(engagement_id, limit=10)
        query, params = c._driver.calls[0]
        assert query.index("WITH n LIMIT $limit") < query.index("OPTIONAL MATCH")
        assert params["limit"] == 10


def test_get_graph_clamps_the_limit_unchanged():
    for requested, expected in ((0, 1), (-5, 1), (10, 10), (999999, 5000), (5000, 5000)):
        c = client()
        c.get_graph("e1", limit=requested)
        assert c._driver.calls[0][1]["limit"] == expected


def test_get_graph_reads_in_a_read_transaction():
    c = client()
    c.get_graph("e1")
    assert c._driver.last_session_kwargs.get("default_access_mode") == "READ"


def test_get_graph_returns_deduped_nodes_and_edges_with_no_dangling_endpoints():
    """Every edge is returned alongside both of its endpoint nodes in the same row, so an edge can
    never reference a node id absent from `nodes` — the UI has nothing to fail to resolve."""
    ip = _Node("n1", "IP", address="10.0.0.5")
    port = _Node("n2", "Port", number=80)
    svc = _Node("n3", "Service", name="http")
    exposes = _Rel("r1", ip, port, "EXPOSES")
    runs = _Rel("r2", port, svc, "RUNS")
    records = [
        {"n": ip, "r": exposes, "m": port},
        {"n": port, "r": runs, "m": svc},
        {"n": ip, "r": exposes, "m": port},   # repeated row: node and edge must not duplicate
        {"n": svc, "r": None, "m": None},     # OPTIONAL MATCH miss
    ]
    out = client(records).get_graph("e1")
    assert set(out.keys()) == {"nodes", "edges"}
    assert [n["id"] for n in out["nodes"]] == ["n1", "n2", "n3"]
    assert out["nodes"][0] == {"id": "n1", "label": "IP", "props": {"address": "10.0.0.5"}}
    assert out["edges"] == [
        {"source": "n1", "target": "n2", "type": "EXPOSES"},
        {"source": "n2", "target": "n3", "type": "RUNS"},
    ]
    node_ids = {n["id"] for n in out["nodes"]}
    for edge in out["edges"]:
        assert edge["source"] in node_ids and edge["target"] in node_ids


# --- B13: the startup backfill must be opt-in ------------------------------------------------------


def test_link_engagement_hosts_does_nothing_unless_asked(monkeypatch):
    monkeypatch.delenv("EYE_GRAPH_BACKFILL_LINKS", raising=False)
    c = client()
    c.link_engagement_hosts()
    assert c._driver.sessions == 0, "a whole-graph backfill must not run on every boot"


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_link_engagement_hosts_runs_when_the_env_var_is_set(monkeypatch, value):
    monkeypatch.setenv("EYE_GRAPH_BACKFILL_LINKS", value)
    c = client()
    c.link_engagement_hosts()
    assert len(c._driver.calls) == 3


def test_link_engagement_hosts_runs_when_forced(monkeypatch):
    monkeypatch.delenv("EYE_GRAPH_BACKFILL_LINKS", raising=False)
    c = client()
    c.link_engagement_hosts(force=True)
    assert len(c._driver.calls) == 3


# --- C2: chains are idempotent and written in one round trip ---------------------------------------


def test_write_attack_chain_is_one_round_trip_with_ordered_steps():
    chain = AttackChain(
        id="deadbeef", engagement_id="e1", title="Attack path on 10.0.0.5",
        risk=Severity.critical, steps=["dk1", "dk2", "dk3"], rationale="why",
    )
    c = client()
    c.write_attack_chain(chain)
    assert len(c._driver.calls) == 1, "steps used to cost one query each"
    query, params = c._driver.calls[0]
    assert "MERGE (c:AttackChain {id: $id})" in query
    assert "SET s.order = step.order" in query
    assert params["steps"] == [
        {"dk": "dk1", "order": 0}, {"dk": "dk2", "order": 1}, {"dk": "dk3", "order": 2},
    ]


def test_correlate_ids_are_stable_across_calls():
    """The MERGE in write_attack_chain keys on chain.id, so a fresh uuid per call made it always
    create: every render of the chains view leaked a duplicate chain plus a STEP edge per finding."""
    findings = [
        mk_finding("10.0.0.5", Severity.low),
        mk_finding("10.0.0.5", Severity.critical, category="nuclei:cve"),
    ]
    first = correlate(findings)
    second = correlate(findings)
    assert [c.id for c in first] == [c.id for c in second]
    assert all(len(c.id) == 32 for c in first), "fixed-width hash token, not a concatenation"


def test_correlate_ids_are_distinct_per_chain_identity():
    shared = "CWE-89"
    findings = [
        mk_finding("app/db.py:42", Severity.high, cwe=shared, category="sast:semgrep"),
        mk_finding("app/api.py:7", Severity.high, cwe=shared, category="sast:semgrep"),
        mk_finding("https://app/q", Severity.high, cwe=shared, category="nuclei:sqli"),
        mk_finding("10.0.0.5", Severity.low),
        mk_finding("10.0.0.5", Severity.high, category="nuclei:cve"),
    ]
    chains = correlate(findings)
    ids = [c.id for c in chains]
    assert len(ids) == len(set(ids)), (
        "two SAST findings sharing a CWE must not collapse onto one chain node whose STEP edges are "
        "the union of both"
    )


# --- B6: schema.cypher must keep up with what the client scans and MERGEs ---------------------------


def _schema_statements() -> list[str]:
    if not SCHEMA.exists():  # pragma: no cover - only when run outside the repo checkout
        pytest.skip(f"{SCHEMA} not available")
    # Mirror apply_schema exactly: strip whole-line '//' comments *before* splitting on ';'.
    body = "\n".join(
        line for line in SCHEMA.read_text().splitlines() if not line.strip().startswith("//")
    )
    return [" ".join(chunk.split()) for chunk in body.split(";") if chunk.strip()]


def test_schema_parses_to_nothing_but_create_statements():
    """Guards the parse order in apply_schema: a ';' inside a '//' comment used to split that comment
    in half and glue its unprefixed tail onto the next statement, silently costing us whichever
    constraint or index happened to follow a comment containing prose punctuation."""
    statements = _schema_statements()
    assert statements
    for stmt in statements:
        assert stmt.startswith("CREATE CONSTRAINT ") or stmt.startswith("CREATE INDEX "), stmt
        assert "IF NOT EXISTS" in stmt, f"apply_schema re-runs on every boot: {stmt}"


def test_service_merge_key_is_backed_by_a_uniqueness_constraint():
    """upsert_service/upsert_services MERGE on (engagement_id, address, port); without the constraint
    that MERGE is a label scan over every Service node and concurrent runs can race into duplicates."""
    statements = _schema_statements()
    assert any(
        "FOR (s:Service) REQUIRE (s.engagement_id, s.address, s.port) IS UNIQUE" in s
        for s in statements
    )


def test_every_scanned_label_has_an_engagement_id_index():
    """get_graph unions one labelled scan per GRAPH_LABELS entry; each needs a single-property
    engagement_id index, or that branch degrades to a label scan."""
    statements = _schema_statements()
    indexed = {
        m.group(1)
        for s in statements
        if (m := re.search(r"FOR \(\w+:(\w+)\) ON \(\w+\.engagement_id\)", s))
    }
    assert set(GRAPH_LABELS) - indexed == set(), (
        f"labels scanned by get_graph with no engagement_id index: {set(GRAPH_LABELS) - indexed}"
    )


def test_attack_chain_id_is_unique():
    """write_attack_chain MERGEs on the content-derived id; the constraint enforces the dedup it is
    meant to provide (and backs the MERGE lookup)."""
    assert any(
        "FOR (c:AttackChain) REQUIRE c.id IS UNIQUE" in s for s in _schema_statements()
    )
