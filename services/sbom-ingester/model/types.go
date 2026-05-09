package model

import "time"

type Image struct {
	ID          string    `json:"id"`
	Digest      string    `json:"digest"`
	Name        string    `json:"name"`
	Tag         string    `json:"tag"`
	Registry    string    `json:"registry"`
	Signed      bool      `json:"signed"`
	SBOMPresent bool      `json:"sbom_present"`
	IngestedAt  time.Time `json:"ingested_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ImageSummary struct {
	Image
	ComponentCount int     `json:"component_count"`
	CriticalCount  int     `json:"critical_count"`
	HighCount      int     `json:"high_count"`
	MediumCount    int     `json:"medium_count"`
	LowCount       int     `json:"low_count"`
	RiskScore      float64 `json:"risk_score"`
}

type Component struct {
	ID      string `json:"id"`
	ImageID string `json:"image_id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Type    string `json:"type"`
}

type Vulnerability struct {
	ID          string  `json:"id"`
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	Description string  `json:"description"`
}

type VulnResult struct {
	Vulnerability
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`
	ComponentPURL    string `json:"component_purl"`
	FixedVersion     string `json:"fixed_version"`
	State            string `json:"state"`
}
