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
from .models import Finding


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class GraphClient:
    def __init__(self, uri: str | None = None, user: str | None = None, password: str | None = None):
        self._driver = GraphDatabase.driver(
            uri or settings.neo4j_uri,
            auth=(user or settings.neo4j_user, password or settings.neo4j_password),
        )

    def close(self) -> None:
        self._driver.close()

    def apply_schema(self, schema_path: str | Path) -> None:
        # schema.cypher is ';'-separated statements, some with leading '//' comment lines.
        # Strip comment lines from each statement, then run the non-empty remainder.
        text = Path(schema_path).read_text()
        with self._driver.session() as session:
            for chunk in text.split(";"):
                stmt = "\n".join(
                    line for line in chunk.splitlines() if not line.strip().startswith("//")
                ).strip()
                if stmt:
                    session.run(stmt)

    def upsert_engagement(self, engagement_id: str, name: str) -> None:
        with self._driver.session() as session:
            session.run(
                "MERGE (e:Engagement {id: $id}) SET e.name = $name",
                id=engagement_id,
                name=name,
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
                """
                MERGE (i:IP {engagement_id: $eid, address: $addr})
                  ON CREATE SET i.first_seen = $now, i.first_run_id = $rid, i.status = 'new'
                  ON MATCH SET i.last_run_id = $rid
                  SET i.last_seen = $now
                MERGE (i)-[:EXPOSES]->(p:Port {engagement_id: $eid, address: $addr, number: $port})
                  ON CREATE SET p.first_seen = $now, p.first_run_id = $rid
                  ON MATCH SET p.last_run_id = $rid
                  SET p.proto = $proto, p.last_seen = $now
                MERGE (p)-[:RUNS]->(s:Service {engagement_id: $eid, address: $addr, port: $port})
                  ON CREATE SET s.first_seen = $now, s.first_run_id = $rid
                  ON MATCH SET s.last_run_id = $rid
                  SET s.name = $service, s.product = $product, s.last_seen = $now
                """,
                eid=engagement_id,
                addr=address,
                port=port,
                proto=proto,
                service=service,
                product=product,
                now=now,
                rid=run_id,
            )

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
                "MERGE (i:IP {engagement_id: $eid, address: $addr}) SET " + ", ".join(sets),
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
        is_url = finding.target.startswith("http://") or finding.target.startswith("https://")
        # Same cross-run bookkeeping as topology nodes: a finding's endpoint/host gets first/last_seen
        # so the memory engine can date it. $rid/$now are bound below.
        affects = (
            "MERGE (t:Endpoint {engagement_id: $eid, url: $target}) "
            "  ON CREATE SET t.first_seen = $now, t.first_run_id = $rid "
            "  ON MATCH SET t.last_run_id = $rid "
            "  SET t.last_seen = $now"
            if is_url
            else "MERGE (t:IP {engagement_id: $eid, address: $target}) "
            "  ON CREATE SET t.first_seen = $now, t.first_run_id = $rid, t.status = 'new' "
            "  ON MATCH SET t.last_run_id = $rid "
            "  SET t.last_seen = $now"
        )
        with self._driver.session() as session:
            session.run(
                """
                MERGE (f:Finding {dedup_key: $dedup})
                  SET f.id = $id, f.engagement_id = $eid, f.run_id = $rid,
                      f.title = $title, f.category = $category, f.severity = $severity,
                      f.state = $state, f.confidence = $confidence, f.target = $target,
                      f.cwe = $cwe, f.cve = $cve, f.cvss_score = $cvss, f.cvss_vector = $vector,
                      f.attack_technique = $tech, f.attack_technique_name = $tech_name,
                      f.evidence = $evidence, f.source_tool = $tool, f.created_at = $created
                """
                + affects +
                """
                MERGE (f)-[:AFFECTS]->(t)
                """,
                dedup=finding.dedup_key(),
                id=finding.id,
                eid=finding.engagement_id,
                rid=finding.run_id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity.value,
                state=finding.state.value,
                confidence=finding.confidence,
                target=finding.target,
                cwe=finding.cwe,
                cve=finding.cve,
                cvss=finding.cvss_score,
                vector=finding.cvss_vector,
                tech=finding.attack_technique,
                tech_name=finding.attack_technique_name,
                evidence=finding.evidence,
                tool=finding.source_tool,
                created=finding.created_at.isoformat(),
                now=_now_iso(),
            )

    def get_graph(self, engagement_id: str | None = None, limit: int = 1000) -> dict:
        """Return nodes and edges for the UI as {nodes: [...], edges: [...]}.

        With no engagement_id this returns the full cross-engagement network map (Maltego-style).
        `limit` caps the rows scanned so a large graph can't return an unbounded payload; the UI
        drills into sub-graphs via the Cypher/entity endpoints when it needs more.
        """
        limit = max(1, min(limit, 5000))
        if engagement_id is None:
            query = "MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m LIMIT $limit"
            params: dict = {"limit": limit}
        else:
            query = (
                "MATCH (n {engagement_id: $eid}) "
                "OPTIONAL MATCH (n)-[r]->(m {engagement_id: $eid}) RETURN n, r, m LIMIT $limit"
            )
            params = {"eid": engagement_id, "limit": limit}
        with self._driver.session() as session:
            result = session.run(query, **params)
            nodes: dict[str, dict] = {}
            edges: list[dict] = []
            for record in result:
                for node in (record["n"], record["m"]):
                    if node is None:
                        continue
                    key = node.element_id
                    if key not in nodes:
                        label = next(iter(node.labels), "Node")
                        nodes[key] = {"id": key, "label": label, "props": dict(node)}
                rel = record["r"]
                if rel is not None:
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
        highlight the path."""
        with self._driver.session() as session:
            session.run(
                "MERGE (c:AttackChain {id: $id}) "
                "SET c.engagement_id = $eid, c.title = $title, c.risk = $risk, c.rationale = $rationale",
                id=chain.id, eid=chain.engagement_id, title=chain.title,
                risk=chain.risk.value, rationale=chain.rationale,
            )
            for order, dedup_key in enumerate(chain.steps):
                session.run(
                    "MATCH (c:AttackChain {id: $id}) MATCH (f:Finding {dedup_key: $dk}) "
                    "MERGE (c)-[s:STEP]->(f) SET s.order = $order",
                    id=chain.id, dk=dedup_key, order=order,
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
