package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Kumar-rahul18/supply-chain-sec/services/sbom-ingester/store"
)

type Handlers struct {
	store *store.Store
}

func NewHandlers(s *store.Store) *Handlers {
	return &Handlers{store: s}
}

// GET /images
func (h *Handlers) ListImages(w http.ResponseWriter, r *http.Request) {
	images, err := h.store.ListImages(r.Context())
	if err != nil {
		slog.Error("list images", "err", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, images)
}

// GET /images/{digest}/vulnerabilities
// digest may be passed with or without the "sha256:" prefix.
func (h *Handlers) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	digest := normaliseDigest(chi.URLParam(r, "digest"))
	vulns, err := h.store.ListVulnerabilities(r.Context(), digest)
	if err != nil {
		slog.Error("list vulns", "digest", digest, "err", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, vulns)
}

// GET /images/{digest}/components
func (h *Handlers) ListComponents(w http.ResponseWriter, r *http.Request) {
	digest := normaliseDigest(chi.URLParam(r, "digest"))
	comps, err := h.store.ListComponents(r.Context(), digest)
	if err != nil {
		slog.Error("list components", "digest", digest, "err", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, comps)
}

// GET /cves/{cveID}/images  — blast radius: all images affected by this CVE
func (h *Handlers) CVEBlastRadius(w http.ResponseWriter, r *http.Request) {
	cveID := chi.URLParam(r, "cveID")
	images, err := h.store.ImagesByVuln(r.Context(), cveID)
	if err != nil {
		slog.Error("blast radius", "cve", cveID, "err", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, images)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}

func normaliseDigest(d string) string {
	if strings.HasPrefix(d, "sha256:") {
		return d
	}
	return "sha256:" + d
}
