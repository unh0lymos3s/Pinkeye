-- Multi-tenancy landed in 0002 as columns only: nothing ever wrote findings.tenant_id,
-- services.tenant_id or runs.tenant_id, so every row carried the 'default' column default and the
-- tenant filter in build_findings_query was a no-op that looked like isolation.
--
-- The write paths now set tenant_id (repositories.py). This backfills the rows written before that
-- from their engagement, which is the authoritative owner of the tenancy relation.

UPDATE findings f
   SET tenant_id = e.tenant_id
  FROM engagements e
 WHERE f.engagement_id = e.id
   AND f.tenant_id IS DISTINCT FROM e.tenant_id;

UPDATE services s
   SET tenant_id = e.tenant_id
  FROM engagements e
 WHERE s.engagement_id = e.id
   AND s.tenant_id IS DISTINCT FROM e.tenant_id;

UPDATE runs r
   SET tenant_id = e.tenant_id
  FROM engagements e
 WHERE r.engagement_id = e.id
   AND r.tenant_id IS DISTINCT FROM e.tenant_id;

-- 0002 indexed engagements and findings by tenant; the other two tables are filtered the same way.
CREATE INDEX IF NOT EXISTS services_tenant ON services(tenant_id);
CREATE INDEX IF NOT EXISTS runs_tenant ON runs(tenant_id);
