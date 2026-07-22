-- Durable, replayable diff log for the cross-run network memory. Each row is one observed change to
-- the map (a new device, a new/closed port, a version change, a newly-exploitable endpoint) so the
-- "what changed between runs" view is audit-grade and survives an API restart. Inherits the same
-- tenancy/RBAC posture as audit_events; stores topology/summaries only, never resolved secrets.
CREATE TABLE IF NOT EXISTS network_observations (
    id            BIGSERIAL PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    kind          TEXT NOT NULL,   -- device | service | endpoint
    key           TEXT NOT NULL,   -- stable identity, e.g. "10.0.0.5:22/tcp" or the URL
    change        TEXT NOT NULL,   -- added | changed | removed | newly_exploitable | unchanged
    before        JSONB,
    after         JSONB,
    at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS network_obs_eng_run ON network_observations(engagement_id, run_id);
