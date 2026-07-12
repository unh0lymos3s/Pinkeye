-- Append-only audit log (previously created ad-hoc by the sink; now a real migration so it exists
-- before the pool-based sink writes to it).
CREATE TABLE IF NOT EXISTS audit_events (
    id            BIGSERIAL PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    type          TEXT NOT NULL,
    detail        TEXT,
    tool          TEXT,
    target        TEXT,
    allowed       BOOLEAN,
    output_sha256 TEXT,
    at            TIMESTAMPTZ NOT NULL,
    payload       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_run ON audit_events(run_id);
