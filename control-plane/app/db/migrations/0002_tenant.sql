-- Phase 7: multi-tenancy. Every row is scoped to a tenant; existing rows fall into 'default'.
-- Combined with API-key RBAC, this keeps one tenant's engagements/findings invisible to another.

ALTER TABLE engagements ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE runs        ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE findings    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE services    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS engagements_tenant ON engagements(tenant_id);
CREATE INDEX IF NOT EXISTS findings_tenant ON findings(tenant_id);

-- Durable job queue: runs are enqueued here and picked up by worker processes. Claiming uses
-- SELECT ... FOR UPDATE SKIP LOCKED so many workers can drain the queue without stepping on each other.
CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    payload       JSONB NOT NULL,
    status        TEXT NOT NULL DEFAULT 'queued',  -- queued | running | done | failed
    claimed_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status, created_at);
