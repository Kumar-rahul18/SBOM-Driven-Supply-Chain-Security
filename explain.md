# SBOM-Driven Supply Chain Security Platform — Deep Dive

## What Problem This Solves

Modern software is assembled, not written. A typical container image contains hundreds of open-source packages pulled in transitively. When a critical vulnerability like Log4Shell or XZ Utils is disclosed, the first question is: **"Which of our running images are affected?"** Without tooling, answering that takes days.

This platform solves three problems:

1. **Visibility** — Know exactly what is inside every image (Software Bill of Materials)
2. **Integrity** — Cryptographically prove an image has not been tampered with (signing)
3. **Enforcement** — Prevent vulnerable or unsigned images from ever running in Kubernetes

---

## Architecture

```
Developer pushes code
        │
        ▼
GitHub Actions CI Pipeline
  ├── Build Docker image
  ├── Push to GHCR (registry)
  ├── Syft → generate SBOM (what's inside the image)
  ├── Cosign → sign image (prove it's legitimate)
  └── Cosign attest → attach SBOM as signed attestation
        │
        ▼
SBOM Ingestion Service (Go + PostgreSQL)
  ├── Parse CycloneDX SBOM → store components
  ├── Grype → scan for CVEs → store vulnerabilities
  └── REST API → serve data
        │
        ▼
Kubernetes Admission Webhook (Phase 3)        React Dashboard (Phase 4)
  ├── Verify signature                           ├── Image inventory
  ├── Check SBOM exists                          ├── CVE blast radius
  └── Enforce CVE threshold policy               └── Compliance view
```

---

## Tools — Detailed Explanation

### Container & Registry

#### Docker
**What:** The industry-standard tool for building and running containers. A container packages your application and all its dependencies into a single portable unit that runs identically everywhere.

**Why here:** Every image in this project is built as a Docker image. We use **multi-stage Dockerfiles** — one stage compiles the Go binary, a separate minimal stage becomes the final image. This keeps images small and reduces attack surface.

**Key concept used:** `distroless/static` as the runtime base — a Google-maintained image with no shell, no package manager, no OS utilities. If an attacker breaks into the container, there is nothing to execute. The only file in the image is the Go binary itself.

---

#### GHCR — GitHub Container Registry
**What:** A Docker-compatible container registry built into GitHub. Images are stored at `ghcr.io/<owner>/<repo>/<image>`.

**Why here:** Free for public repositories, natively integrated with GitHub Actions (no separate registry credentials needed — `GITHUB_TOKEN` works), and supports OCI artifacts (needed to store Cosign signatures and SBOM attestations alongside the image).

**Key detail:** GHCR requires all image names to be **lowercase**. Repository names like `SBOM-Driven-Supply-Chain-Security` must be normalised to `sbom-driven-supply-chain-security` before being used as image names.

---

### Local Kubernetes

#### kind — Kubernetes IN Docker
**What:** A tool that runs a full Kubernetes cluster inside Docker containers. Each "node" of the cluster is a Docker container on your laptop.

**Why here instead of minikube:** kind starts faster, uses less memory, integrates better with CI, and the cluster config is a single YAML file you can version-control. Our config creates one control-plane node and two worker nodes.

**Why Kubernetes at all:** The admission webhook (Phase 3) is a Kubernetes-native concept. You need a real cluster to deploy and test it. kind gives you a production-equivalent cluster locally without any cloud cost.

---

#### kubectl
**What:** The command-line interface for Kubernetes. Every operation on the cluster — deploying workloads, inspecting pods, checking logs — goes through `kubectl`.

**Why here:** Required to interact with the kind cluster and to deploy the admission webhook, cert-manager, and application manifests.

---

#### Helm
**What:** The package manager for Kubernetes. A "chart" is a collection of Kubernetes manifests templated with values, versioned, and packaged for distribution.

**Why here:** Phase 5 packages the entire platform (ingestion service + webhook + postgres) as a Helm chart so it can be deployed to any cluster with a single command. Without Helm, deploying requires applying dozens of individual YAML files in the correct order.

---

### CI/CD

#### GitHub Actions
**What:** GitHub's built-in CI/CD system. Workflows are YAML files in `.github/workflows/` that run automatically on git events (push, PR, schedule).

**Why here:** Free for public repos, runs on `ubuntu-latest` runners with Docker pre-installed, provides a native OIDC token that Cosign uses for keyless signing (no secrets to manage), and uploads artifacts (SBOMs) that can be downloaded later.

**Our workflow does:** checkout → lowercase image name → Docker build + push → install Cosign + Syft → generate SBOM → sign image → attest SBOM → upload SBOM artifact → (optionally) POST to ingestion service.

---

### SBOM — Software Bill of Materials

#### Syft (by Anchore)
**What:** An open-source tool that inspects a container image or filesystem and produces a complete list of every software package inside it — name, version, type, and PURL (Package URL).

**Why here:** Syft is the most widely adopted SBOM generator. It supports both major SBOM formats (CycloneDX and SPDX), understands dozens of package ecosystems (apk, deb, rpm, npm, pip, Go modules, etc.), and integrates natively with Cosign for attaching SBOMs as signed attestations.

**Output formats used:**
- `cyclonedx-json` — primary format, parsed by the ingestion service and Grype
- `spdx-json` — secondary format, stored as an artifact for compliance tooling

**What a PURL is:** Package URL — a standardised identifier for a software package across ecosystems. Example: `pkg:apk/alpine/musl@1.2.5-r0` identifies the `musl` C library version `1.2.5-r0` from the Alpine apk ecosystem. PURLs are the key used to link SBOM components to vulnerability findings.

---

#### CycloneDX
**What:** An SBOM standard created by OWASP. Defines a JSON/XML schema for describing software components, their relationships, licenses, and vulnerabilities.

**Why here over SPDX:** CycloneDX is more focused on security use cases, has better tooling support in the vulnerability scanning ecosystem (Grype, Dependency-Track), and the JSON format is compact and easy to parse in Go. SPDX is generated too for broad compatibility.

**Structure:**
```json
{
  "bomFormat": "CycloneDX",
  "components": [
    {
      "type": "library",
      "name": "musl",
      "version": "1.2.5-r0",
      "purl": "pkg:apk/alpine/musl@1.2.5-r0"
    }
  ]
}
```

---

### Image Signing — Sigstore Stack

#### Cosign (by Sigstore)
**What:** A tool for signing and verifying container images. A signature proves that a specific image digest was produced by a specific identity.

**Why here:** Cosign is the standard signing tool for supply chain security. It supports **keyless signing** — no private key to manage, rotate, or accidentally leak. Signatures and attestations (like SBOMs) are stored as OCI artifacts in the same registry as the image.

**Two uses in this project:**
1. `cosign sign` — signs the image digest. Creates a signature stored at `ghcr.io/.../sample-app:sha256-<hash>.sig`
2. `cosign attest` — attaches the SBOM as a signed attestation. Stored at `ghcr.io/.../sample-app:sha256-<hash>.att`

---

#### Fulcio (Sigstore CA)
**What:** A free public Certificate Authority that issues short-lived (10-minute) code-signing certificates tied to an OIDC identity.

**Why here:** This is what makes keyless signing possible. Instead of: *"here is my private key, trust me"*, it says: *"GitHub's OIDC provider vouches that this workflow at this repo signed this image"*. The certificate binds the public key to the workflow identity (`https://github.com/Kumar-rahul18/SBOM-Driven-Supply-Chain-Security/.github/workflows/build-sign-sbom.yml`).

**Flow:**
```
GitHub Actions Job
      │ presents OIDC token (proof of identity)
      ▼
Fulcio CA
      │ issues x509 cert valid for 10 minutes
      ▼
Cosign signs image with ephemeral key pair
      │ cert + signature logged permanently
      ▼
Rekor transparency log
```

---

#### Rekor (Sigstore Transparency Log)
**What:** An immutable, append-only public log of every signing event. Similar to Certificate Transparency logs for TLS certificates.

**Why here:** Once a signing event is in Rekor, it cannot be deleted or modified. This means:
- You can prove an image was signed at a specific time
- You can detect if someone is trying to sign images outside the CI pipeline
- Auditors can independently verify the entire signing history

**Verification:** `cosign verify` automatically checks Rekor to confirm the signature is in the log and the certificate was valid at signing time.

---

### Vulnerability Scanning

#### Grype (by Anchore)
**What:** An open-source vulnerability scanner that matches software components against CVE databases (NVD, GitHub Advisories, OS-specific advisories like Alpine SecDB).

**Why here:** Grype accepts a CycloneDX SBOM as input directly (`grype sbom:file.json`), meaning it scans the bill of materials rather than re-inspecting the image. This is faster and works without Docker access. It outputs structured JSON with CVE ID, severity, CVSS score, affected package, and fix version.

**Output structure (simplified):**
```json
{
  "matches": [{
    "vulnerability": {
      "id": "CVE-2024-1234",
      "severity": "High",
      "cvss": [{"metrics": {"baseScore": 7.5}}],
      "fix": {"versions": ["1.2.3"], "state": "fixed"}
    },
    "artifact": {
      "name": "libssl",
      "version": "1.1.1",
      "purl": "pkg:apk/alpine/libssl1.1@1.1.1"
    }
  }]
}
```

**CVSS Score:** Common Vulnerability Scoring System — a 0–10 number representing severity. 9–10 = Critical, 7–8.9 = High, 4–6.9 = Medium, 0.1–3.9 = Low.

---

### Backend Service

#### Go (Golang)
**What:** A compiled, statically typed language from Google. Produces a single self-contained binary with no runtime dependencies.

**Why here:**
- **Small containers:** The Go binary + distroless base = ~10MB image. A Python or Node.js equivalent would be 100–400MB.
- **Performance:** Compiles to native code, handles thousands of concurrent HTTP requests.
- **Standard library:** `net/http`, `encoding/json`, `log/slog` cover most needs without external dependencies.
- **Supply chain:** Fewer dependencies = smaller attack surface = less to put in the SBOM.

---

#### PostgreSQL
**What:** An open-source relational database. Stores structured data with ACID guarantees, supports complex joins, and has excellent JSON support.

**Why here:**
- The data model (images → components → vulnerabilities) is naturally relational — foreign keys enforce integrity
- The blast radius query (`"show me all images with CVE-X"`) is a multi-table join that SQL handles elegantly
- `gen_random_uuid()` generates UUIDs natively
- `ON CONFLICT DO UPDATE` (upsert) handles re-ingesting the same image without duplicates

**Schema design:**
```
images ──< components ──< component_vulns >── vulnerabilities
```
A many-to-many between components and vulnerabilities, mediated by `component_vulns` which also stores the fix version and remediation state.

---

#### pgx/v5
**What:** The most feature-complete PostgreSQL driver for Go. Supports connection pooling, batch queries, and the full PostgreSQL type system.

**Why over `database/sql`:** `pgx` exposes `SendBatch` which sends multiple INSERT statements in a single round-trip to the database — critical for upserting hundreds of components from a large SBOM efficiently.

---

#### chi (go-chi/chi)
**What:** A lightweight HTTP router for Go built on the standard `net/http` interface.

**Why over Gin/Echo:** chi has zero non-stdlib dependencies, uses standard `http.Handler` interfaces (no lock-in), and provides URL parameter extraction (`chi.URLParam`) and middleware chaining without magic.

---

### Infrastructure as Code

#### docker-compose.yml
**What:** Defines a multi-container local development environment. One command (`docker compose up`) starts PostgreSQL and the ingestion service in the correct order with the correct environment variables.

**Why:** Eliminates "works on my machine" problems. Any developer cloning the repo can run the full stack with no manual configuration.

---

#### cert-manager (Phase 3)
**What:** A Kubernetes controller that automatically provisions and renews TLS certificates using Let's Encrypt or a self-signed CA.

**Why needed in Phase 3:** Kubernetes admission webhooks require TLS — the API server will refuse to call a webhook over plain HTTP. cert-manager handles certificate issuance and rotation automatically so the webhook server always has a valid cert.

---

## Project Phases

### Phase 1 — Foundation (Complete)

**Goal:** End-to-end pipeline producing signed images with verified SBOMs.

**What was built:**
- Sample Go HTTP app with health endpoint, version injected at build time
- Distroless Dockerfile (no shell in final image)
- GitHub Actions workflow: build → push GHCR → Syft SBOM → Cosign keyless sign → attest
- kind cluster config (1 control-plane + 2 workers)
- `scripts/verify.sh` — CLI verification of signature and SBOM attestation

**How to verify it worked:**
```bash
cosign verify \
  --certificate-identity-regexp='https://github.com/Kumar-rahul18/.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/kumar-rahul18/sbom-driven-supply-chain-security/sample-app@sha256:<digest>
```

**Key insight:** Keyless signing means zero secrets in GitHub. The OIDC token GitHub provides IS the identity proof. Fulcio issues a cert, Rekor logs it, and the signature is verifiable by anyone forever.

---

### Phase 2 — Storage & Ingestion (Complete)

**Goal:** Persist SBOM data and vulnerability findings in a queryable database, expose a REST API.

**What was built:**

| Component | Purpose |
|---|---|
| PostgreSQL schema | 4 tables: images, components, vulnerabilities, component_vulns |
| `db` package | Connection pool + idempotent schema migration on startup |
| `store` package | All SQL operations with batch upserts |
| `ingest/cyclonedx.go` | Parses CycloneDX JSON → domain types, deduplicates by PURL |
| `ingest/grype.go` | Execs grype as subprocess, parses JSON output |
| `ingest/handler.go` | `POST /ingest` — orchestrates parse → store → scan → link |
| `api/handlers.go` | REST API — image list, vulnerabilities, components, blast radius |
| `docker-compose.yml` | Local stack: postgres + ingestion service |

**REST API:**
```
POST /ingest                          — ingest a new SBOM + trigger Grype scan
GET  /images                          — list all images with risk scores
GET  /images/{digest}/vulnerabilities — CVEs for one image, sorted by severity
GET  /images/{digest}/components      — SBOM components for one image
GET  /cves/{cveID}/images             — blast radius: all images with this CVE
```

**Risk Score formula:**
```
risk_score = (CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1) / component_count
```
Normalising by component count prevents large images (more packages = more CVEs naturally) from appearing worse than small images with genuinely dangerous vulnerabilities.

**PURL matching challenge:** Grype and Syft can produce slightly different PURL qualifiers for the same package (e.g., different `?arch=` or `?distro=` strings). The ingestion handler strips query-string qualifiers before matching, ensuring vulnerability findings are linked to the correct component even when PURLs don't match exactly.

---

### Phase 3 — Admission Webhook (Planned)

**Goal:** Block non-compliant images from being deployed to Kubernetes.

**What will be built:**
- Go `ValidatingAdmissionWebhook` server that intercepts every Pod creation
- Policy checks: signature verified? SBOM present? Critical CVE count within threshold?
- TLS via cert-manager (required by Kubernetes)
- `ValidatingWebhookConfiguration` Kubernetes manifest
- Audit mode flag (log violations without blocking) for safe rollout

**Why this matters:** SBOM generation and scanning in CI is advisory — a developer can still manually push and deploy an unscanned image. The webhook closes that gap. If the image doesn't meet policy at deploy time, Kubernetes rejects it.

---

### Phase 4 — Dashboard (Planned)

**Goal:** A React UI that makes the data from Phase 2 actionable.

**What will be built:**
- **Image Inventory** — table with signed status, SBOM present, risk score, CVE breakdown
- **Image Detail** — drill into components and their CVEs
- **CVE Blast Radius** — input a CVE ID, see every affected image instantly
- **Compliance View** — which images pass policy, which don't, and why
- **Rekor Audit Trail** — show the transparency log entries for any image

**Tech stack:** React + TypeScript + Vite, TanStack Query, shadcn/ui + Tailwind, Recharts.

---

### Phase 5 — Polish (Planned)

**Goal:** Make the platform production-ready and demonstrable.

**What will be built:**
- Webhook notifications when a new CVE affects images (Slack/email)
- SLSA provenance verification in the admission webhook
- Helm chart packaging the entire platform for one-command deployment
- Architecture diagram in README
- Demo script automating the full end-to-end showcase

---

## Key Concepts Summary

| Concept | Definition |
|---|---|
| SBOM | A complete, machine-readable inventory of every software component in an artifact |
| CVE | Common Vulnerabilities and Exposures — a numbered identifier for a known security flaw |
| CVSS | A 0–10 score representing how severe a CVE is |
| PURL | Package URL — a standard identifier for a package across ecosystems |
| Keyless signing | Signing without a long-lived private key; identity comes from OIDC, cert from Fulcio |
| Attestation | A signed statement about an artifact (e.g., "this image's SBOM is X") stored in the registry |
| Admission webhook | A Kubernetes extension point that can approve or reject API server requests |
| Blast radius | The set of all images affected by a specific CVE |
| Distroless | A container base image with no OS tools — only CA certificates and the app binary |
