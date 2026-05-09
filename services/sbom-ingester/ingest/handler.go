package ingest

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Kumar-rahul18/supply-chain-sec/services/sbom-ingester/model"
	"github.com/Kumar-rahul18/supply-chain-sec/services/sbom-ingester/store"
)

type IngestRequest struct {
	ImageName   string          `json:"image_name"`
	ImageTag    string          `json:"image_tag"`
	ImageDigest string          `json:"image_digest"`
	Registry    string          `json:"registry"`
	Signed      bool            `json:"signed"`
	SBOM        json.RawMessage `json:"sbom"`
}

type IngestResponse struct {
	ImageID        string `json:"image_id"`
	ComponentCount int    `json:"component_count"`
	VulnCount      int    `json:"vuln_count"`
}

type Handler struct {
	store *store.Store
}

func NewHandler(s *store.Store) *Handler {
	return &Handler{store: s}
}

func (h *Handler) Ingest(w http.ResponseWriter, r *http.Request) {
	var req IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ImageDigest == "" {
		http.Error(w, "image_digest is required", http.StatusBadRequest)
		return
	}
	if len(req.SBOM) == 0 {
		http.Error(w, "sbom is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	imageID, err := h.store.UpsertImage(ctx, model.Image{
		Digest:      req.ImageDigest,
		Name:        req.ImageName,
		Tag:         req.ImageTag,
		Registry:    req.Registry,
		Signed:      req.Signed,
		SBOMPresent: true,
	})
	if err != nil {
		slog.Error("upsert image", "err", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	components, err := ParseCycloneDX([]byte(req.SBOM))
	if err != nil {
		http.Error(w, "invalid SBOM: "+err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("parsed SBOM", "digest", req.ImageDigest, "components", len(components))

	purlToID, err := h.store.UpsertComponents(ctx, imageID, components)
	if err != nil {
		slog.Error("upsert components", "err", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	findings, err := RunGrype([]byte(req.SBOM))
	if err != nil {
		// Grype failure (e.g. DB not yet downloaded) should not block ingestion.
		slog.Warn("grype scan skipped", "err", err)
	}
	slog.Info("grype scan", "digest", req.ImageDigest, "findings", len(findings))

	vulnCount := 0
	for _, f := range findings {
		compID := purlToID[f.ArtifactPURL]
		if compID == "" {
			compID = matchPURLPrefix(purlToID, f.ArtifactPURL)
		}
		if compID == "" {
			slog.Debug("unmatched artifact purl", "purl", f.ArtifactPURL, "cve", f.Vulnerability.CVEID)
			continue
		}

		vulnID, err := h.store.UpsertVulnerability(ctx, f.Vulnerability)
		if err != nil {
			slog.Error("upsert vuln", "cve", f.Vulnerability.CVEID, "err", err)
			continue
		}
		if err := h.store.LinkComponentVuln(ctx, compID, vulnID, f.FixedVersion, f.State); err != nil {
			slog.Error("link component vuln", "err", err)
			continue
		}
		vulnCount++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(IngestResponse{
		ImageID:        imageID,
		ComponentCount: len(components),
		VulnCount:      vulnCount,
	})

	slog.Info("ingest complete", "digest", req.ImageDigest, "components", len(components), "vulns", vulnCount)
}

// matchPURLPrefix handles the case where Grype and Syft generate slightly
// different query-string qualifiers on the same base PURL.
func matchPURLPrefix(purlToID map[string]string, purl string) string {
	base := stripPURLQualifiers(purl)
	for p, id := range purlToID {
		if stripPURLQualifiers(p) == base {
			return id
		}
	}
	return ""
}

func stripPURLQualifiers(purl string) string {
	if i := strings.IndexByte(purl, '?'); i >= 0 {
		return purl[:i]
	}
	return purl
}
