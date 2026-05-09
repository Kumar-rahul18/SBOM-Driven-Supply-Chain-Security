CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS images (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    digest       TEXT        NOT NULL UNIQUE,
    name         TEXT        NOT NULL,
    tag          TEXT        NOT NULL DEFAULT '',
    registry     TEXT        NOT NULL DEFAULT '',
    signed       BOOLEAN     NOT NULL DEFAULT FALSE,
    sbom_present BOOLEAN     NOT NULL DEFAULT FALSE,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS components (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    image_id UUID NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    version  TEXT NOT NULL DEFAULT '',
    purl     TEXT NOT NULL DEFAULT '',
    type     TEXT NOT NULL DEFAULT 'library',
    UNIQUE (image_id, purl)
);

CREATE INDEX IF NOT EXISTS idx_components_image_id ON components(image_id);
CREATE INDEX IF NOT EXISTS idx_components_purl     ON components(purl);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id       TEXT        NOT NULL UNIQUE,
    severity     TEXT        NOT NULL,
    cvss_score   NUMERIC(4,1),
    description  TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_vulns_cve_id   ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

CREATE TABLE IF NOT EXISTS component_vulns (
    component_id  UUID NOT NULL REFERENCES components(id)      ON DELETE CASCADE,
    vuln_id       UUID NOT NULL REFERENCES vulnerabilities(id)  ON DELETE CASCADE,
    fixed_version TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL DEFAULT 'unknown',
    PRIMARY KEY (component_id, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_cv_component_id ON component_vulns(component_id);
CREATE INDEX IF NOT EXISTS idx_cv_vuln_id      ON component_vulns(vuln_id);
