-- Local known-CVE database. Seeded from a data file (see app.cve_seed) or synced from NVD, this is
-- what the agent queries to map a discovered product/version to known vulnerabilities offline.
CREATE TABLE IF NOT EXISTS cves (
    cve_id      TEXT PRIMARY KEY,
    product     TEXT NOT NULL,
    version     TEXT,          -- affected version or range, matched loosely
    cvss_score  REAL,
    cvss_vector TEXT,
    cwe         TEXT,
    description TEXT,
    published   DATE
);
CREATE INDEX IF NOT EXISTS cves_product ON cves(lower(product));
