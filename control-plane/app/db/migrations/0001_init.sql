-- Pinkeye system-of-record. Postgres is the durable memory: engagements, runs, findings, and
-- discovered services persist here across restarts and power the dashboard KPIs and query API.
-- Neo4j holds the same facts as a graph for the network map; this is the relational mirror.

CREATE TABLE IF NOT EXISTS engagements (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    scope      JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS runs (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    target        TEXT NOT NULL,
    tool          TEXT,
    intensity     TEXT,
    status        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS runs_engagement ON runs(engagement_id);

-- Findings are keyed by dedup_key so the same issue re-observed across runs updates in place and
-- increments times_seen instead of duplicating — this is how the harness "remembers".
CREATE TABLE IF NOT EXISTS findings (
    dedup_key     TEXT PRIMARY KEY,
    id            TEXT NOT NULL,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    run_id        TEXT NOT NULL,
    title         TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    state         TEXT NOT NULL,
    confidence    REAL NOT NULL,
    target        TEXT NOT NULL,
    cwe           TEXT,
    cve           TEXT,
    evidence      TEXT,
    source_tool   TEXT,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    times_seen    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS findings_cve ON findings(cve) WHERE cve IS NOT NULL;

-- One row per discovered IP:port/service; drives the "exposed endpoints / open ports" KPIs.
CREATE TABLE IF NOT EXISTS services (
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    address       TEXT NOT NULL,
    port          INTEGER NOT NULL,
    proto         TEXT NOT NULL,
    service       TEXT,
    product       TEXT,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (engagement_id, address, port, proto)
);
CREATE INDEX IF NOT EXISTS services_engagement ON services(engagement_id);
