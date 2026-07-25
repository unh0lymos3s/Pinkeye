-- Indexes for the search and dashboard read paths.
--
-- Three hot queries use leading-wildcard matching, which no btree index can serve:
--   * query.build_findings_query  -> findings.title ILIKE '%q%'
--   * ServiceRepo.search          -> services.address/service/product ILIKE '%q%'
--   * CveRepo.lookup              -> lower(cves.product) LIKE '%p%'
-- Trigram GIN indexes make all three index-backed. pg_trgm needs to be installable by the
-- migrating role; if it is not, we skip the trigram indexes rather than failing the whole
-- migration (and, with it, API startup) — the queries then behave exactly as they do today.

DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'pg_trgm unavailable (%); skipping trigram indexes', SQLERRM;
    END;

    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS findings_title_trgm ON findings USING gin (title gin_trgm_ops)';
        -- ServiceRepo.search ORs across all three columns, so all three need an index or the
        -- planner falls back to a sequential scan regardless.
        EXECUTE 'CREATE INDEX IF NOT EXISTS services_address_trgm ON services USING gin (address gin_trgm_ops)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS services_service_trgm ON services USING gin (service gin_trgm_ops)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS services_product_trgm ON services USING gin (product gin_trgm_ops)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS cves_product_trgm ON cves USING gin (lower(product) gin_trgm_ops)';
    END IF;
END$$;

-- NOTE: build_findings_query's free-text filter is (title ILIKE %s OR evidence ILIKE %s). Only
-- `title` is indexed here on purpose: `evidence` holds raw tool-output snippets, and a trigram GIN
-- over it would be very large. Until it is indexed too, that OR still costs a sequential scan.
-- To index it anyway, and accept the size:
--   CREATE INDEX findings_evidence_trgm ON findings USING gin (evidence gin_trgm_ops);

-- Matches build_findings_query's "ORDER BY cvss_score DESC, last_seen DESC, dedup_key" for the
-- common "findings for an engagement" read, so the paging walk in FindingRepo.iter_findings does not
-- re-sort the whole filtered set per page. dedup_key is the trailing key because the query needs it
-- as a tiebreaker to make the ordering total (see iter_findings); including it here makes the whole
-- ORDER BY index-ordered rather than leaving a per-page partial sort on the last column.
CREATE INDEX IF NOT EXISTS findings_eng_score
    ON findings (engagement_id, cvss_score DESC, last_seen DESC, dedup_key);

-- Transcript reads are "events for a run, in seq order" / "seq > N". seq is monotonic per run, so
-- the pair is a natural key: making the index unique also stops the best-effort event persister
-- from writing a duplicate row on a retry. De-duplicate first (keeping the earliest row) so the
-- index creation cannot fail on historical data.
DELETE FROM run_events a
    USING run_events b
    WHERE a.run_id = b.run_id AND a.seq = b.seq AND a.id > b.id;

CREATE UNIQUE INDEX IF NOT EXISTS run_events_run_seq_uniq ON run_events (run_id, seq);
-- Superseded by the unique index above: same columns, same order.
DROP INDEX IF EXISTS run_events_run_seq;
