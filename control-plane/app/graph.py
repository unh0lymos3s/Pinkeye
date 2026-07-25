"""Neo4j knowledge-graph client.

Writes are idempotent (MERGE on the same uniqueness keys as schema.cypher), so re-running a scan
updates the graph in place instead of duplicating nodes. The UI reads `get_graph` to render the
nodes and edges for an engagement.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from neo4j import GraphDatabase

from .config import settings
from .envknobs import env_flag
from .models import Finding


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Every label this client writes. `get_graph` unions labelled (index-backed) scans over these instead
# of an unlabelled `MATCH (n {engagement_id: ...})`, which no label-scoped index can serve and which
# therefore plans an AllNodesScan over the whole database.
GRAPH_LABELS = (
    "Engagement", "IP", "Domain", "Port", "Service", "Endpoint", "Finding", "AttackChain",
)

# --- Shared Cypher fragments -------------------------------------------------------------------
# The engagement MERGE + DISCOVERED edge used to be copy-pasted into upsert_service, set_device and
# record_finding; the three copies drifting apart is what made the link_engagement_hosts backfill
# necessary in the first place. They are single-sourced here. Each fragment takes the *expressions*
# to interpolate so the same text serves both the singular ($param) and the batched (row.field)
# forms — the MERGE keys and the first_seen/last_seen bookkeeping stay identical between them,
# which the cross-run memory engine depends on.


def _merge_engagement(eid: str = "$eid") -> str:
    """Bind `e` to the Engagement node, mirroring engagement_id onto it (see upsert_engagement)."""
    return f"MERGE (e:Engagement {{id: {eid}}}) SET e.engagement_id = {eid}"


def _merge_discovered(node: str) -> str:
    """Engagement -> discovered host/endpoint edge. Requires `e` and `node` already bound."""
    return f"MERGE (e)-[:DISCOVERED]->({node})"


def _merge_topology(
    eid: str = "$eid", addr: str = "$addr", port: str = "$port", proto: str = "$proto",
    service: str = "$service", product: str = "$product", rid: str = "$rid", now: str = "$now",
) -> str:
    """IP -> Port -> Service chain with cross-run bookkeeping. Requires `e` already bound."""
    return f"""
        MERGE (i:IP {{engagement_id: {eid}, address: {addr}}})
          ON CREATE SET i.first_seen = {now}, i.first_run_id = {rid}, i.status = 'new'
          ON MATCH SET i.last_run_id = {rid}
          SET i.last_seen = {now}
        {_merge_discovered('i')}
        MERGE (i)-[:EXPOSES]->(p:Port {{engagement_id: {eid}, address: {addr}, number: {port}}})
          ON CREATE SET p.first_seen = {now}, p.first_run_id = {rid}
          ON MATCH SET p.last_run_id = {rid}
          SET p.proto = {proto}, p.last_seen = {now}
        MERGE (p)-[:RUNS]->(s:Service {{engagement_id: {eid}, address: {addr}, port: {port}}})
          ON CREATE SET s.first_seen = {now}, s.first_run_id = {rid}
          ON MATCH SET s.last_run_id = {rid}
          SET s.name = {service}, s.product = {product}, s.last_seen = {now}
    """


def _merge_affected(
    is_url: bool, eid: str = "$eid", target: str = "$target", rid: str = "$rid", now: str = "$now",
) -> str:
    """Bind `t` to what a finding affects: an Endpoint for web targets, an IP for everything else.

    Same cross-run bookkeeping as the topology nodes, so the memory engine can date them.
    """
    if is_url:
        return f"""
        MERGE (t:Endpoint {{engagement_id: {eid}, url: {target}}})
          ON CREATE SET t.first_seen = {now}, t.first_run_id = {rid}
          ON MATCH SET t.last_run_id = {rid}
          SET t.last_seen = {now}
        """
    return f"""
        MERGE (t:IP {{engagement_id: {eid}, address: {target}}})
          ON CREATE SET t.first_seen = {now}, t.first_run_id = {rid}, t.status = 'new'
          ON MATCH SET t.last_run_id = {rid}
          SET t.last_seen = {now}
        """


def _set_finding_props(ref: str = "$") -> str:
    """Property writes for a Finding node. `ref` is '$' for bound params, 'row.' for UNWIND rows;
    the field names are identical in both cases so the two forms cannot drift."""
    return f"""
        SET f.id = {ref}id, f.engagement_id = {ref}eid, f.run_id = {ref}rid,
            f.title = {ref}title, f.category = {ref}category, f.severity = {ref}severity,
            f.state = {ref}state, f.confidence = {ref}confidence, f.target = {ref}target,
            f.cwe = {ref}cwe, f.cve = {ref}cve, f.cvss_score = {ref}cvss, f.cvss_vector = {ref}vector,
            f.attack_technique = {ref}tech, f.attack_technique_name = {ref}tech_name,
            f.evidence = {ref}evidence, f.source_tool = {ref}tool, f.created_at = {ref}created
    """


def _service_row(service) -> dict:
    """Flatten one service observation into the UNWIND row consumed by `_merge_topology`.

    Accepts either a plain dict — the documented `upsert_services` contract, because this module must
    not import the runtime's `ServiceObservation` (the dependency runs control-plane -> runtime, not
    back) — or any object exposing the same five attribute names, which is what
    `orchestrator._persist_services` hands over today. Supporting both is what lets the two sides
    land independently; the row it produces is identical either way.

    `address`/`port` are required (they are two thirds of the Service MERGE key, so a missing one
    would silently create a junk node keyed on null); the rest default exactly as the singular
    `upsert_service` signature does. Note the defaults only fire when the field is *absent* — an
    explicitly empty proto is passed through unchanged, so the batch cannot write a different
    `p.proto` than the singular path would for the same input.
    """
    if isinstance(service, dict):
        return {
            "addr": service["address"],
            "port": service["port"],
            "proto": service.get("proto", "tcp"),
            "service": service.get("service", "") or "",
            "product": service.get("product", "") or "",
        }
    return {
        "addr": service.address,
        "port": service.port,
        "proto": getattr(service, "proto", "tcp"),
        "service": getattr(service, "service", "") or "",
        "product": getattr(service, "product", "") or "",
    }


def _finding_row(finding: Finding) -> dict:
    """Flatten a Finding into the parameter map consumed by `_set_finding_props`."""
    return {
        "dedup": finding.dedup_key(),
        "id": finding.id,
        "eid": finding.engagement_id,
        "rid": finding.run_id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity.value,
        "state": finding.state.value,
        "confidence": finding.confidence,
        "target": finding.target,
        "cwe": finding.cwe,
        "cve": finding.cve,
        "cvss": finding.cvss_score,
        "vector": finding.cvss_vector,
        "tech": finding.attack_technique,
        "tech_name": finding.attack_technique_name,
        "evidence": finding.evidence,
        "tool": finding.source_tool,
        "created": finding.created_at.isoformat(),
    }


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


class GraphClient:
    def __init__(self, uri: str | None = None, user: str | None = None, password: str | None = None):
        self._driver = GraphDatabase.driver(
            uri or settings.neo4j_uri,
            auth=(user or settings.neo4j_user, password or settings.neo4j_password),
        )

    def close(self) -> None:
        self._driver.close()

    def _write(self, query: str, **params) -> None:
        """Run a write in a managed transaction, which the driver retries on transient failures.

        The batch writers use this rather than an autocommit `session.run`: a batch carries a whole
        tool step's rows, so losing it to a deadlock (more likely now that one transaction touches
        many nodes) would be expensive, and every statement here is MERGE-idempotent so a retry is
        safe.
        """
        with self._driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, **params).consume())

    def apply_schema(self, schema_path: str | Path) -> None:
        # schema.cypher is ';'-separated statements interleaved with whole-line '//' comments.
        #
        # Comments are stripped *before* splitting on ';', not after, and the order matters: prose in
        # a comment routinely contains a semicolon ("...is written; until then it guards the key"),
        # and splitting first cuts that comment in half. The tail half no longer carries its '//'
        # prefix, so it survives the per-chunk comment filter and gets glued onto the front of the
        # next statement — which then fails to parse. That silently cost us the domain_key
        # constraint and the ip_status index, both of which sit directly after such a comment.
        #
        # One failing statement must not skip the rest of the file either: a constraint that cannot
        # be created (e.g. `service_key` when duplicate Service nodes predate it) would otherwise
        # silently prevent every later index from ever being applied. Apply them all, then report.
        text = Path(schema_path).read_text()
        body = "\n".join(
            line for line in text.splitlines() if not line.strip().startswith("//")
        )
        failures: list[str] = []
        for chunk in body.split(";"):
            stmt = chunk.strip()
            if not stmt:
                continue
            # One session per statement, and .consume() to force execution: the driver's run() is
            # lazy, so without consuming, a failure would surface against an unrelated later
            # statement (and leave the session's connection in a failed state).
            try:
                with self._driver.session() as session:
                    session.run(stmt).consume()
            except Exception as exc:  # noqa: BLE001 - reported in aggregate below
                failures.append(f"{stmt.splitlines()[0].strip()}: {exc}")
        if failures:
            raise RuntimeError("schema statements failed: " + "; ".join(failures))

    def upsert_engagement(self, engagement_id: str, name: str) -> None:
        with self._driver.session() as session:
            # engagement_id mirrors id so the Engagement node is included by the per-engagement graph
            # query (which filters on engagement_id) and thus shows as the root of its discovered hosts.
            session.run(
                "MERGE (e:Engagement {id: $id}) SET e.name = $name, e.engagement_id = $id",
                id=engagement_id,
                name=name,
            )

    def link_engagement_hosts(self, force: bool = False) -> None:
        """One-off backfill for data written before engagement->host linking existed: stamp
        engagement_id on Engagement nodes and MERGE a DISCOVERED edge to every IP/Endpoint under them.

        This is a *migration*, not startup work. It scans every IP and Endpoint in the database, so
        its cost grows with total graph size forever and it delays readiness on every boot — while
        `upsert_service`/`record_finding` already MERGE the DISCOVERED edge inline, so nothing written
        by the current code needs it. It is therefore opt-in: set EYE_GRAPH_BACKFILL_LINKS=1 (or pass
        force=True) to run it. Idempotent, so re-running it is safe.
        """
        if not force and not env_flag("EYE_GRAPH_BACKFILL_LINKS"):
            return
        with self._driver.session() as session:
            session.run("MATCH (e:Engagement) WHERE e.engagement_id IS NULL SET e.engagement_id = e.id")
            session.run(
                "MATCH (i:IP) MATCH (e:Engagement {id: i.engagement_id}) "
                "MERGE (e)-[:DISCOVERED]->(i)"
            )
            session.run(
                "MATCH (t:Endpoint) MATCH (e:Engagement {id: t.engagement_id}) "
                "MERGE (e)-[:DISCOVERED]->(t)"
            )

    def upsert_service(
        self,
        engagement_id: str,
        address: str,
        port: int,
        proto: str,
        service: str = "",
        product: str = "",
        run_id: str | None = None,
    ) -> None:
        """Create the IP -> Port -> Service topology discovered by a recon tool.

        Cross-run bookkeeping (first_seen/first_run_id on create, last_seen/last_run_id on match) is
        set on every node in the chain. These timestamps are what let the memory engine diff the map
        between runs directly from the graph. The MERGE keys are unchanged, so nothing duplicates.
        The IP node doubles as the Device; a fresh IP starts life with status 'new'.
        """
        now = _now_iso()
        with self._driver.session() as session:
            session.run(
                _merge_engagement() + _merge_topology(),
                eid=engagement_id,
                addr=address,
                port=port,
                proto=proto,
                service=service,
                product=product,
                now=now,
                rid=run_id,
            )

    def upsert_services(
        self, engagement_id: str, services: list[dict], run_id: str | None = None
    ) -> None:
        """Batched `upsert_service`: one session, one transaction, one round trip for the whole list.

        `services` is a list of plain dicts — `{"address", "port", "proto", "service", "product"}` —
        and not the runtime's `ServiceObservation`, since graph.py cannot import from agent-runtime;
        objects carrying those attribute names are accepted too (see `_service_row`). A single
        `nmap -p-` can emit thousands of rows, and calling the singular method per row costs one
        Neo4j session, one transaction and one round trip each. An empty list returns immediately.

        The MERGE keys and the ON CREATE/ON MATCH first_seen/last_seen/first_run_id/last_run_id
        bookkeeping are byte-identical to `upsert_service` (both compose `_merge_topology`), so the
        two paths are interchangeable and the cross-run memory diff is unaffected.
        """
        rows = [_service_row(s) for s in (services or [])]
        if not rows:
            return
        # Collapse repeats on the Service MERGE key, keeping the last occurrence. A run of sequential
        # `upsert_service` calls would have left the last row's name/product on the node, so this is
        # what makes the batch provably equivalent to them rather than dependent on the planner
        # inserting an Eager operator between UNWIND and MERGE to make repeated keys converge.
        # Then sorted, so concurrent batches touching the same hosts take node locks in one order.
        deduped = {(str(r["addr"]), str(r["port"])): r for r in rows}
        rows = sorted(deduped.values(), key=lambda r: (str(r["addr"]), str(r["port"])))
        query = (
            _merge_engagement()
            + " WITH e UNWIND $rows AS row "
            + _merge_topology(
                addr="row.addr", port="row.port", proto="row.proto",
                service="row.service", product="row.product",
            )
        )
        self._write(query, rows=rows, eid=engagement_id, rid=run_id, now=_now_iso())

    def set_device(
        self,
        engagement_id: str,
        address: str,
        status: str | None = None,
        is_target: bool | None = None,
        hostname: str | None = None,
        os: str | None = None,
        device_type: str | None = None,
    ) -> None:
        """Roll the memory engine's derived device state (status / is_target / identity) onto the IP
        node so the network map can style it. Only non-None fields are written."""
        sets, params = [], {"eid": engagement_id, "addr": address}
        for name, value in (
            ("status", status), ("is_target", is_target),
            ("hostname", hostname), ("os", os), ("device_type", device_type),
        ):
            if value is not None:
                sets.append(f"i.{name} = ${name}")
                params[name] = value
        if not sets:
            return
        with self._driver.session() as session:
            session.run(
                "MERGE (i:IP {engagement_id: $eid, address: $addr}) SET " + ", ".join(sets)
                + " " + _merge_engagement()
                + " " + _merge_discovered("i"),
                **params,
            )

    def flag_exploitable(
        self,
        engagement_id: str,
        finding_dedup: str,
        address: str | None = None,
        port: int | None = None,
        url: str | None = None,
    ) -> None:
        """Mark a Service (by address+port) or Endpoint (by url) exploitable and link it to the
        finding that proves it via an EXPLOITABLE_VIA edge, so the map and agent can see *why*."""
        with self._driver.session() as session:
            if url is not None:
                session.run(
                    """
                    MERGE (e:Endpoint {engagement_id: $eid, url: $url}) SET e.exploitable = true
                    WITH e MATCH (f:Finding {dedup_key: $dk}) MERGE (e)-[:EXPLOITABLE_VIA]->(f)
                    """,
                    eid=engagement_id, url=url, dk=finding_dedup,
                )
            elif address is not None and port is not None:
                session.run(
                    """
                    MATCH (s:Service {engagement_id: $eid, address: $addr, port: $port})
                      SET s.exploitable = true
                    WITH s MATCH (f:Finding {dedup_key: $dk}) MERGE (s)-[:EXPLOITABLE_VIA]->(f)
                    """,
                    eid=engagement_id, addr=address, port=port, dk=finding_dedup,
                )

    def load_devices(self, engagement_id: str) -> list[dict]:
        """Reconstruct the current device -> service-cluster view from the graph, so the memory engine
        can warm its state after an API restart. Best-effort; returns [] on any error upstream."""
        query = (
            "MATCH (i:IP {engagement_id: $eid}) "
            "OPTIONAL MATCH (i)-[:EXPOSES]->(p:Port)-[:RUNS]->(s:Service) "
            "RETURN i AS device, collect({port: p.number, proto: p.proto, service: s.name, "
            "product: s.product, exploitable: coalesce(s.exploitable, false), "
            "last_run_id: s.last_run_id}) AS services"
        )
        with self._driver.session(default_access_mode="READ") as session:
            out = []
            for rec in session.run(query, eid=engagement_id):
                dev = dict(rec["device"])
                dev["services"] = [s for s in rec["services"] if s.get("port") is not None]
                out.append(dev)
            return out

    def record_finding(self, finding: Finding) -> None:
        """Write a normalized finding and attach it to what it affects.

        Web findings carry a URL target and attach to an Endpoint node; everything else attaches to
        an IP node. This keeps the network map correct instead of turning URLs into fake hosts.
        """
        query = (
            "MERGE (f:Finding {dedup_key: $dedup})"
            + _set_finding_props("$")
            + _merge_affected(_is_url(finding.target))
            + " MERGE (f)-[:AFFECTS]->(t) "
            + _merge_engagement()
            + " " + _merge_discovered("t")
        )
        with self._driver.session() as session:
            session.run(query, now=_now_iso(), **_finding_row(finding))

    def record_findings(self, findings: list[Finding]) -> None:
        """Batched `record_finding`: one round trip for web-targeted findings and one for the rest,
        instead of one Neo4j session per finding. An empty list returns immediately.

        `findings` is a list of `app.models.Finding`. The node MERGE keys and the AFFECTS/DISCOVERED
        edges are identical to the singular method (both compose the same fragments); the list is
        split by target kind only because a URL target attaches to an Endpoint and everything else to
        an IP, exactly as `record_finding` decides per finding. Two round trips is the floor for a
        mixed batch: the two branches MERGE different labels, so they cannot share one UNWIND.
        """
        url_rows, host_rows = [], []
        for finding in findings or []:
            (url_rows if _is_url(finding.target) else host_rows).append(_finding_row(finding))
        if not url_rows and not host_rows:
            return
        now = _now_iso()
        for is_url, rows in ((True, url_rows), (False, host_rows)):
            if not rows:
                continue
            # Collapse repeats on the Finding MERGE key keeping the last occurrence (what sequential
            # `record_finding` calls would leave behind), then sort so concurrent batches take
            # Finding locks in the same order (deadlock hygiene).
            rows = sorted({r["dedup"]: r for r in rows}.values(), key=lambda r: r["dedup"])
            query = (
                "UNWIND $rows AS row "
                "MERGE (f:Finding {dedup_key: row.dedup})"
                + _set_finding_props("row.")
                + _merge_affected(is_url, eid="row.eid", target="row.target", rid="row.rid")
                + " MERGE (f)-[:AFFECTS]->(t) "
                + _merge_engagement("row.eid")
                + " " + _merge_discovered("t")
            )
            self._write(query, rows=rows, now=now)

    def get_graph(self, engagement_id: str | None = None, limit: int = 1000) -> dict:
        """Return nodes and edges for the UI as {nodes: [...], edges: [...]}.

        With no engagement_id this returns the full cross-engagement network map (Maltego-style).

        Both variants scan by *label* so the engagement_id indexes in schema.cypher are reachable —
        an unlabelled `MATCH (n {engagement_id: ...})` cannot use any index (they are all
        label-scoped) and plans an AllNodesScan, making a per-engagement read cost scale with the
        size of the entire database. `limit` is applied to *nodes*, before relationships are
        expanded: applying it to rows let a single hub node with many relationships crowd every
        other node out of the payload, so the map rendered wrong rather than merely truncated.
        A secondary row cap keeps the response bounded when such a hub node is present.

        Dangling edges are impossible by construction rather than by a filtering pass: every row
        carries an edge together with *both* of its endpoints, and both are added to `nodes`, so no
        edge can reference an id the UI cannot resolve. The trade is that the `m` side may be a node
        outside the limited set, so len(nodes) can exceed `limit` — bounded by the row cap. The
        alternative (dropping edges whose endpoints fall outside the node limit) would silently hide
        real topology at the edge of the window; keeping the endpoint is the honest truncation.

        Labels are interpolated into the query text because Cypher cannot parameterize a label. They
        come only from the module-level GRAPH_LABELS tuple — a closed internal allowlist, never
        caller input — which is the same narrow exception `set_device` makes for property names.
        Every actual *value* here ($eid, $limit, $row_limit) is still a bound parameter.
        """
        limit = max(1, min(limit, 5000))
        if engagement_id is None:
            scan = " UNION ".join(f"MATCH (n:{label}) RETURN n" for label in GRAPH_LABELS)
            expand = "OPTIONAL MATCH (n)-[r]->(m)"
            params: dict = {}
        else:
            scan = " UNION ".join(
                f"MATCH (n:{label} {{engagement_id: $eid}}) RETURN n" for label in GRAPH_LABELS
            )
            expand = "OPTIONAL MATCH (n)-[r]->(m {engagement_id: $eid})"
            params = {"eid": engagement_id}
        query = (
            f"CALL {{ {scan} }} WITH n LIMIT $limit "
            f"{expand} RETURN n, r, m LIMIT $row_limit"
        )
        params.update({"limit": limit, "row_limit": limit * 20})
        with self._driver.session(default_access_mode="READ") as session:
            result = session.run(query, **params)
            nodes: dict[str, dict] = {}
            edges: list[dict] = []
            seen_edges: set[str] = set()
            for record in result:
                for node in (record["n"], record["m"]):
                    if node is None:
                        continue
                    key = node.element_id
                    if key not in nodes:
                        label = next(iter(node.labels), "Node")
                        nodes[key] = {"id": key, "label": label, "props": dict(node)}
                rel = record["r"]
                if rel is not None and rel.element_id not in seen_edges:
                    seen_edges.add(rel.element_id)
                    edges.append(
                        {
                            "source": rel.start_node.element_id,
                            "target": rel.end_node.element_id,
                            "type": rel.type,
                        }
                    )
            return {"nodes": list(nodes.values()), "edges": edges}

    def write_attack_chain(self, chain) -> None:
        """Write an AttackChain node with ordered STEP edges to its member findings, so the map can
        highlight the path.

        The node and all of its steps go in one round trip (it used to be one query *per step*).
        This is only idempotent because `correlate` derives `chain.id` from the engagement, the chain
        kind and its key rather than minting a fresh uuid — with a fresh id the MERGE always created,
        so every call left behind a duplicate chain.
        """
        with self._driver.session() as session:
            session.run(
                "MERGE (c:AttackChain {id: $id}) "
                "SET c.engagement_id = $eid, c.title = $title, c.risk = $risk, c.rationale = $rationale "
                "WITH c UNWIND $steps AS step "
                "MATCH (f:Finding {dedup_key: step.dk}) "
                "MERGE (c)-[s:STEP]->(f) SET s.order = step.order",
                id=chain.id, eid=chain.engagement_id, title=chain.title,
                risk=chain.risk.value, rationale=chain.rationale,
                steps=[{"dk": dk, "order": order} for order, dk in enumerate(chain.steps)],
            )

    def run_read_query(self, cypher: str, params: dict | None = None, limit: int = 500) -> list[dict]:
        """Run a caller-supplied Cypher query inside a READ transaction.

        The transaction is the hard guarantee: Neo4j refuses any write attempted in it, so even a
        query that slips past the lexical guard cannot mutate the graph. Returns row dicts.
        """
        def _work(tx):
            result = tx.run(cypher, **(params or {}))
            rows = []
            for record in result:
                row = {}
                for key in record.keys():
                    value = record[key]
                    # Nodes/relationships aren't JSON-serializable; expose their properties.
                    row[key] = dict(value) if hasattr(value, "keys") else value
                rows.append(row)
                if len(rows) >= limit:
                    break
            return rows

        with self._driver.session(default_access_mode="READ") as session:
            return session.execute_read(_work)
