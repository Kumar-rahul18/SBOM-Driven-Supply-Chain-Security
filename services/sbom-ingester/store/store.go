package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Kumar-rahul18/supply-chain-sec/services/sbom-ingester/model"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) UpsertImage(ctx context.Context, img model.Image) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO images (digest, name, tag, registry, signed, sbom_present)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (digest) DO UPDATE SET
			name         = EXCLUDED.name,
			tag          = EXCLUDED.tag,
			registry     = EXCLUDED.registry,
			signed       = EXCLUDED.signed,
			sbom_present = EXCLUDED.sbom_present,
			updated_at   = NOW()
		RETURNING id`,
		img.Digest, img.Name, img.Tag, img.Registry, img.Signed, img.SBOMPresent,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert image: %w", err)
	}
	return id, nil
}

// UpsertComponents upserts all components in a single batch and returns a purl→id map.
func (s *Store) UpsertComponents(ctx context.Context, imageID string, comps []model.Component) (map[string]string, error) {
	if len(comps) == 0 {
		return map[string]string{}, nil
	}

	batch := &pgx.Batch{}
	for _, c := range comps {
		batch.Queue(`
			INSERT INTO components (image_id, name, version, purl, type)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (image_id, purl) DO UPDATE SET
				name    = EXCLUDED.name,
				version = EXCLUDED.version,
				type    = EXCLUDED.type
			RETURNING id`,
			imageID, c.Name, c.Version, c.PURL, c.Type,
		)
	}

	results := s.pool.SendBatch(ctx, batch)

	purlToID := make(map[string]string, len(comps))
	for _, c := range comps {
		var id string
		if err := results.QueryRow().Scan(&id); err != nil {
			results.Close()
			return nil, fmt.Errorf("upsert component %s: %w", c.Name, err)
		}
		purlToID[c.PURL] = id
	}
	return purlToID, results.Close()
}

func (s *Store) UpsertVulnerability(ctx context.Context, v model.Vulnerability) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, cvss_score, description)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (cve_id) DO UPDATE SET
			severity    = EXCLUDED.severity,
			cvss_score  = EXCLUDED.cvss_score,
			description = EXCLUDED.description
		RETURNING id`,
		strings.ToUpper(v.CVEID), strings.ToUpper(v.Severity), v.CVSSScore, v.Description,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert vuln %s: %w", v.CVEID, err)
	}
	return id, nil
}

func (s *Store) LinkComponentVuln(ctx context.Context, componentID, vulnID, fixedVersion, state string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO component_vulns (component_id, vuln_id, fixed_version, state)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (component_id, vuln_id) DO UPDATE SET
			fixed_version = EXCLUDED.fixed_version,
			state         = EXCLUDED.state`,
		componentID, vulnID, fixedVersion, state,
	)
	return err
}

func (s *Store) ListImages(ctx context.Context) ([]model.ImageSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			i.id, i.digest, i.name, i.tag, i.registry, i.signed, i.sbom_present,
			i.ingested_at, i.updated_at,
			COUNT(DISTINCT c.id)::int                                                              AS component_count,
			COUNT(DISTINCT CASE WHEN UPPER(v.severity) = 'CRITICAL' THEN cv.vuln_id END)::int     AS critical_count,
			COUNT(DISTINCT CASE WHEN UPPER(v.severity) = 'HIGH'     THEN cv.vuln_id END)::int     AS high_count,
			COUNT(DISTINCT CASE WHEN UPPER(v.severity) = 'MEDIUM'   THEN cv.vuln_id END)::int     AS medium_count,
			COUNT(DISTINCT CASE WHEN UPPER(v.severity) = 'LOW'      THEN cv.vuln_id END)::int     AS low_count
		FROM images i
		LEFT JOIN components c    ON c.image_id    = i.id
		LEFT JOIN component_vulns cv ON cv.component_id = c.id
		LEFT JOIN vulnerabilities v  ON v.id           = cv.vuln_id
		GROUP BY i.id
		ORDER BY i.ingested_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.ImageSummary
	for rows.Next() {
		var s model.ImageSummary
		if err := rows.Scan(
			&s.ID, &s.Digest, &s.Name, &s.Tag, &s.Registry, &s.Signed, &s.SBOMPresent,
			&s.IngestedAt, &s.UpdatedAt,
			&s.ComponentCount, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount,
		); err != nil {
			return nil, err
		}
		if s.ComponentCount > 0 {
			s.RiskScore = float64(s.CriticalCount*10+s.HighCount*5+s.MediumCount*2+s.LowCount) /
				float64(s.ComponentCount)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Store) ListVulnerabilities(ctx context.Context, digest string) ([]model.VulnResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			v.id, v.cve_id, v.severity, COALESCE(v.cvss_score, 0), v.description,
			c.name, c.version, c.purl,
			cv.fixed_version, cv.state
		FROM images i
		JOIN components c       ON c.image_id    = i.id
		JOIN component_vulns cv ON cv.component_id = c.id
		JOIN vulnerabilities v  ON v.id           = cv.vuln_id
		WHERE i.digest = $1
		ORDER BY
			CASE UPPER(v.severity)
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH'     THEN 2
				WHEN 'MEDIUM'   THEN 3
				WHEN 'LOW'      THEN 4
				ELSE 5
			END,
			v.cvss_score DESC NULLS LAST`,
		digest,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.VulnResult
	for rows.Next() {
		var r model.VulnResult
		if err := rows.Scan(
			&r.ID, &r.CVEID, &r.Severity, &r.CVSSScore, &r.Description,
			&r.ComponentName, &r.ComponentVersion, &r.ComponentPURL,
			&r.FixedVersion, &r.State,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListComponents(ctx context.Context, digest string) ([]model.Component, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.image_id, c.name, c.version, c.purl, c.type
		FROM images i
		JOIN components c ON c.image_id = i.id
		WHERE i.digest = $1
		ORDER BY c.name, c.version`,
		digest,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Component
	for rows.Next() {
		var c model.Component
		if err := rows.Scan(&c.ID, &c.ImageID, &c.Name, &c.Version, &c.PURL, &c.Type); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ImagesByVuln returns all images affected by a given CVE ID (blast radius query).
func (s *Store) ImagesByVuln(ctx context.Context, cveID string) ([]model.ImageSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT
			i.id, i.digest, i.name, i.tag, i.registry, i.signed, i.sbom_present,
			i.ingested_at, i.updated_at,
			0::int, 0::int, 0::int, 0::int, 0::int
		FROM images i
		JOIN components c       ON c.image_id     = i.id
		JOIN component_vulns cv ON cv.component_id = c.id
		JOIN vulnerabilities v  ON v.id            = cv.vuln_id
		WHERE UPPER(v.cve_id) = UPPER($1)
		ORDER BY i.ingested_at DESC`,
		cveID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.ImageSummary
	for rows.Next() {
		var s model.ImageSummary
		if err := rows.Scan(
			&s.ID, &s.Digest, &s.Name, &s.Tag, &s.Registry, &s.Signed, &s.SBOMPresent,
			&s.IngestedAt, &s.UpdatedAt,
			&s.ComponentCount, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
