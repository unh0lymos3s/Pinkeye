-- CVSS score + MITRE ATT&CK technique on findings, so severity is comparable and expressible in
-- defender terms. Existing rows default to 0/unknown until re-observed.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score REAL NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_vector TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_technique TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_technique_name TEXT;

CREATE INDEX IF NOT EXISTS findings_attack ON findings(attack_technique) WHERE attack_technique IS NOT NULL;
