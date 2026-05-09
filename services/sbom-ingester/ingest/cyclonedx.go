package ingest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Kumar-rahul18/supply-chain-sec/services/sbom-ingester/model"
)

type cdxBOM struct {
	BOMFormat  string         `json:"bomFormat"`
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// ParseCycloneDX extracts domain Components from a CycloneDX JSON payload.
func ParseCycloneDX(data []byte) ([]model.Component, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parse cyclonedx: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("unexpected bomFormat: %q", bom.BOMFormat)
	}

	seen := make(map[string]bool, len(bom.Components))
	out := make([]model.Component, 0, len(bom.Components))

	for _, c := range bom.Components {
		purl := strings.TrimSpace(c.PURL)
		if purl == "" {
			purl = fmt.Sprintf("pkg:generic/%s@%s", c.Name, c.Version)
		}
		if seen[purl] {
			continue
		}
		seen[purl] = true

		t := c.Type
		if t == "" {
			t = "library"
		}
		out = append(out, model.Component{
			Name:    c.Name,
			Version: c.Version,
			PURL:    purl,
			Type:    t,
		})
	}
	return out, nil
}
