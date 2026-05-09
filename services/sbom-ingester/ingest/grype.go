package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Kumar-rahul18/supply-chain-sec/services/sbom-ingester/model"
)

type GrypeFinding struct {
	Vulnerability model.Vulnerability
	ArtifactPURL  string
	FixedVersion  string
	State         string
}

type grypeScanResult struct {
	Matches []gryeMatch `json:"matches"`
}

type gryeMatch struct {
	Vulnerability gryeVuln     `json:"vulnerability"`
	Artifact      gryeArtifact `json:"artifact"`
}

type gryeVuln struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
	CVSS        []grypeCVSS `json:"cvss"`
	Fix         grypeFix    `json:"fix"`
}

type grypeCVSS struct {
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type gryeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// RunGrype writes sbomJSON to a temp file, executes grype against it,
// and returns parsed vulnerability findings.
func RunGrype(sbomJSON []byte) ([]GrypeFinding, error) {
	f, err := os.CreateTemp("", "sbom-*.cyclonedx.json")
	if err != nil {
		return nil, fmt.Errorf("create temp sbom: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(sbomJSON); err != nil {
		f.Close()
		return nil, fmt.Errorf("write temp sbom: %w", err)
	}
	f.Close()

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("grype", "sbom:"+f.Name(), "-o", "json", "-q")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("grype exited: %w — %s", err, stderr.String())
	}

	var result grypeScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse grype output: %w", err)
	}

	out := make([]GrypeFinding, 0, len(result.Matches))
	for _, m := range result.Matches {
		purl := m.Artifact.PURL
		if purl == "" {
			purl = fmt.Sprintf("pkg:generic/%s@%s", m.Artifact.Name, m.Artifact.Version)
		}

		fixedVersion := strings.Join(m.Vulnerability.Fix.Versions, ", ")
		state := m.Vulnerability.Fix.State
		if state == "" {
			state = "unknown"
		}

		out = append(out, GrypeFinding{
			Vulnerability: model.Vulnerability{
				CVEID:       m.Vulnerability.ID,
				Severity:    strings.ToUpper(m.Vulnerability.Severity),
				CVSSScore:   maxBaseScore(m.Vulnerability.CVSS),
				Description: m.Vulnerability.Description,
			},
			ArtifactPURL: purl,
			FixedVersion: fixedVersion,
			State:        state,
		})
	}
	return out, nil
}

func maxBaseScore(scores []grypeCVSS) float64 {
	var max float64
	for _, s := range scores {
		if s.Metrics.BaseScore > max {
			max = s.Metrics.BaseScore
		}
	}
	return max
}
