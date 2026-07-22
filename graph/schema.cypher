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
