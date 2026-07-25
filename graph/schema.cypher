// Pinkeye — Neo4j schema (constraints + indexes).
// Applied once at stack startup. Uniqueness keys keep the graph deduplicated as tools re-report
// the same hosts, ports, and findings across runs.

CREATE CONSTRAINT engagement_id IF NOT EXISTS
  FOR (e:Engagement) REQUIRE e.id IS UNIQUE;

CREATE CONSTRAINT run_id IF NOT EXISTS
  FOR (r:Run) REQUIRE r.id IS UNIQUE;

// Hosts and IPs are unique within an engagement, not globally (two engagements may see 10.0.0.5).
CREATE CONSTRAINT ip_key IF NOT EXISTS
  FOR (i:IP) REQUIRE (i.engagement_id, i.address) IS UNIQUE;

// RESERVED (R9): nothing writes a :Domain node today — a hostname target becomes an :IP or an
// :Endpoint. Kept rather than dropped, deliberately: `get_graph` already unions over the Domain
// label (graph.py LABELS), a constraint on a label with no nodes costs nothing to hold, and dropping
// the line would not drop the constraint from already-provisioned databases (CREATE ... IF NOT
// EXISTS only ever adds) — so removing it buys nothing and desynchronizes this file from deployed
// graphs. It becomes live the moment domain topology is written; until then it guards the key.
CREATE CONSTRAINT domain_key IF NOT EXISTS
  FOR (d:Domain) REQUIRE (d.engagement_id, d.name) IS UNIQUE;

CREATE CONSTRAINT port_key IF NOT EXISTS
  FOR (p:Port) REQUIRE (p.engagement_id, p.address, p.number) IS UNIQUE;

CREATE CONSTRAINT endpoint_key IF NOT EXISTS
  FOR (e:Endpoint) REQUIRE (e.engagement_id, e.url) IS UNIQUE;

CREATE CONSTRAINT finding_key IF NOT EXISTS
  FOR (f:Finding) REQUIRE f.dedup_key IS UNIQUE;

CREATE INDEX finding_engagement IF NOT EXISTS
  FOR (f:Finding) ON (f.engagement_id);

CREATE INDEX ip_engagement IF NOT EXISTS
  FOR (i:IP) ON (i.engagement_id);

// Cross-run memory: index the bookkeeping the memory engine diffs on. No new uniqueness keys — the
// MERGE keys are unchanged, so nothing duplicates; these only speed up "what changed" / status reads.
CREATE INDEX ip_status IF NOT EXISTS
  FOR (i:IP) ON (i.status);

CREATE INDEX ip_last_run IF NOT EXISTS
  FOR (i:IP) ON (i.last_run_id);

CREATE INDEX service_last_run IF NOT EXISTS
  FOR (s:Service) ON (s.last_run_id);

// Services are keyed by (engagement, address, port) — the same key `upsert_service`/`upsert_services`
// MERGE on. Without this the MERGE degrades to a label scan over every Service node in the database,
// and concurrent runs can race into duplicate Service nodes because nothing enforces the key.
// NOTE: creation FAILS on a database that already contains duplicate Service nodes. apply_schema
// deliberately continues past a failing statement, so the rest of this file still applies and the
// stack still starts — but the constraint is silently absent until an operator dedupes. To check and
// repair, run the two queries in the OPERATOR RUNBOOK comment at the bottom of this file, then
// restart the API (apply_schema is idempotent and will pick the constraint up).
CREATE CONSTRAINT service_key IF NOT EXISTS
  FOR (s:Service) REQUIRE (s.engagement_id, s.address, s.port) IS UNIQUE;

// AttackChain ids are content-derived (correlation._chain_id), so this both backs the MERGE in
// write_attack_chain and enforces the deduplication it is meant to provide.
CREATE CONSTRAINT attack_chain_id IF NOT EXISTS
  FOR (c:AttackChain) REQUIRE c.id IS UNIQUE;

// Per-engagement reads (`get_graph`) union one labelled scan per label in `graph.GRAPH_LABELS`, so
// *every* one of those labels needs a single-property engagement_id index for its branch to be
// index-backed rather than a label scan. Composite constraint keys (Port, Endpoint, Domain) are not
// relied on to serve a lookup on engagement_id alone. `test_graph_cypher` asserts this list stays in
// step with GRAPH_LABELS, so adding a label to the client without an index here fails the suite.
CREATE INDEX service_engagement IF NOT EXISTS
  FOR (s:Service) ON (s.engagement_id);

CREATE INDEX endpoint_engagement IF NOT EXISTS
  FOR (e:Endpoint) ON (e.engagement_id);

CREATE INDEX port_engagement IF NOT EXISTS
  FOR (p:Port) ON (p.engagement_id);

CREATE INDEX attack_chain_engagement IF NOT EXISTS
  FOR (c:AttackChain) ON (c.engagement_id);

// Engagement is keyed on `id`; `engagement_id` mirrors it (upsert_engagement) purely so the node is
// picked up by the per-engagement scan, which means that scan needs its own index on the mirror.
CREATE INDEX engagement_engagement IF NOT EXISTS
  FOR (e:Engagement) ON (e.engagement_id);

// Domain holds no nodes today (see the RESERVED note above), so this index costs nothing to hold —
// it exists so the Domain branch of the per-engagement scan is index-backed the moment it does.
CREATE INDEX domain_engagement IF NOT EXISTS
  FOR (d:Domain) ON (d.engagement_id);

// ===================================================================================================
// OPERATOR RUNBOOK — dedupe Service nodes before `service_key` can be created
// ===================================================================================================
// Only needed once, on a database written by a build that predates the service_key constraint (before
// it, concurrent runs could race two MERGEs into two nodes with the same key). Run these by hand in
// cypher-shell / Neo4j Browser; they are commented out here so apply_schema never executes them.
//
// STEP 1 — inspect, read-only. Reports each duplicated key and how many copies exist. If this returns
// no rows, there is nothing to repair and the constraint will create cleanly.
//
//   MATCH (s:Service)
//   WITH s.engagement_id AS eid, s.address AS addr, s.port AS port, collect(s) AS dupes
//   WHERE size(dupes) > 1
//   RETURN eid, addr, port, size(dupes) AS copies ORDER BY copies DESC
//
// STEP 2 — collapse each group onto one surviving node. Take a backup first; this deletes nodes.
//
//   MATCH (s:Service)
//   WITH s.engagement_id AS eid, s.address AS addr, s.port AS port, collect(s) AS dupes
//   WHERE size(dupes) > 1
//   // Survivor = the oldest copy, so first_seen/first_run_id (which the memory engine diffs on)
//   // survives the merge. A null first_seen sorts last: ISO timestamps all begin with a digit < '9'.
//   WITH dupes, reduce(keep = head(dupes), n IN tail(dupes) |
//          CASE WHEN coalesce(n.first_seen, '9') < coalesce(keep.first_seen, '9') THEN n ELSE keep END
//        ) AS keep
//   UNWIND [d IN dupes WHERE d <> keep] AS dup
//   // dup_is_newer is computed before any SET runs, so the two CASEs below cannot read a value that
//   // an earlier SET item in the same clause has already overwritten.
//   WITH keep, dup, coalesce(dup.last_seen, '') > coalesce(keep.last_seen, '') AS dup_is_newer
//   SET keep.exploitable = coalesce(keep.exploitable, false) OR coalesce(dup.exploitable, false),
//       keep.last_seen   = CASE WHEN dup_is_newer THEN dup.last_seen   ELSE keep.last_seen   END,
//       keep.last_run_id = CASE WHEN dup_is_newer THEN dup.last_run_id ELSE keep.last_run_id END
//   WITH keep, dup
//   // The inbound (:Port)-[:RUNS]->(:Service) edge needs no rewiring: port_key makes the parent Port
//   // unique per (engagement, address, number), so every copy already hangs off that same Port and
//   // the survivor is already attached to it. Only the exploitability evidence must be carried over.
//   OPTIONAL MATCH (dup)-[:EXPLOITABLE_VIA]->(f:Finding)
//   WITH keep, dup, collect(f) AS evidence
//   FOREACH (f IN evidence | MERGE (keep)-[:EXPLOITABLE_VIA]->(f))
//   DETACH DELETE dup
//
// STEP 3 — re-run STEP 1 to confirm zero rows, then restart the API to create the constraint.
// ===================================================================================================
