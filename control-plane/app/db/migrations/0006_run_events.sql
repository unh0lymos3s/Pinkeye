-- Live run-event stream (chat transcript). Best-effort durable copy of the in-memory ring buffer so
-- a run can be replayed/reconnected after the fact, mirroring the audit_events pattern. Inherits the
-- same tenancy/RBAC posture as audit data; stores summaries and prose only, never resolved secrets.
CREATE TABLE IF NOT EXISTS run_events (
    id            BIGSERIAL PRIMARY KEY,
    run_id        TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    seq           INT  NOT NULL,          -- monotonic per run; drives ordered replay + tailing
    kind          TEXT NOT NULL,
    data          JSONB NOT NULL,
    at            TIMESTAMPTZ NOT NULL
);
-- Reads are always "events for a run, in seq order" (transcript) or "seq > N" (tail).
CREATE INDEX IF NOT EXISTS run_events_run_seq ON run_events(run_id, seq);
