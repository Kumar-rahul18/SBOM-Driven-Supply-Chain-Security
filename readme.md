# Software Supply Chain Security Platform

A end-to-end platform for securing the software supply chain: SBOM generation, image signing, vulnerability scanning, Kubernetes admission enforcement, and a compliance dashboard.

## Architecture

```
GitHub Repo → CI Pipeline → Build Image → Sign (Cosign/Sigstore)
                                 ↓
                         SBOM (Syft) attached as attestation
                                 ↓
                   Ingestion Service (Go) → PostgreSQL
                                 ↓
                         Grype vuln scan
                                 ↓
          ┌──────────────────────┴──────────────────────┐
    Admission Webhook                           React Dashboard
    (K8s enforcement)                   (Inventory / CVE / Compliance)
```

## Phases

| Phase | Status | Description |
|---|---|---|
| 1 — Foundation | ✅ | K8s cluster, CI pipeline, Syft SBOMs, Cosign signing |
| 2 — Storage | 🔜 | PostgreSQL schema, Go ingestion service, Grype, REST API |
| 3 — Enforcement | 🔜 | Admission webhook, policy engine |
| 4 — Dashboard | 🔜 | React UI, CVE blast radius, compliance view |
| 5 — Polish | 🔜 | Webhook notifications, SLSA, Helm chart |

---

## Phase 1 — Foundation

### Prerequisites

Install the following tools:

| Tool | Install |
|---|---|
| Docker | https://docs.docker.com/get-docker/ |
| kind | `go install sigs.k8s.io/kind@latest` or https://kind.sigs.k8s.io/docs/user/quick-start/ |
| kubectl | https://kubernetes.io/docs/tasks/tools/ |
| cosign | `go install github.com/sigstore/cosign/v2/cmd/cosign@latest` |
| syft | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh -s -- -b /usr/local/bin` |
| grype | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh -s -- -b /usr/local/bin` |
| helm | https://helm.sh/docs/intro/install/ |

Verify everything is installed:
```bash
make check-tools
```

### 1. Create the local Kubernetes cluster

```bash
make cluster-up
# Creates a 1 control-plane + 2 worker kind cluster named "supply-chain-sec"
```

Verify:
```bash
kubectl get nodes
# NAME                              STATUS   ROLES           AGE
# supply-chain-sec-control-plane    Ready    control-plane   1m
# supply-chain-sec-worker           Ready    <none>          1m
# supply-chain-sec-worker2          Ready    <none>          1m
```

### 2. Build the sample app locally

```bash
make build VERSION=0.1.0
make run          # visit http://localhost:8080/health
```

### 3. Set up GitHub repository

1. Create a new GitHub repo (e.g., `your-org/supply-chain-sec`)
2. Update `go.mod` — replace `your-org` with your GitHub org/username
3. Update `Makefile` — set `ORG ?= your-org`
4. Push to GitHub:
   ```bash
   git init
   git remote add origin https://github.com/your-org/supply-chain-sec.git
   git add .
   git commit -m "phase 1: foundation"
   git push -u origin main
   ```
5. Enable GHCR for the repository: GitHub → Settings → Packages → Allow GitHub Actions to create packages

### 4. GitHub Actions Pipeline

The workflow at [.github/workflows/build-sign-sbom.yml](.github/workflows/build-sign-sbom.yml) triggers on any push to `main` that touches `apps/sample-app/`. It:

1. Builds the Docker image and pushes to `ghcr.io/<org>/supply-chain-sec/sample-app`
2. Generates SBOMs in both **CycloneDX** and **SPDX** formats using Syft
3. Signs the image with **Cosign keyless** — no key management needed:
   - GitHub provides an OIDC token
   - Fulcio CA issues a short-lived certificate bound to the workflow identity
   - The signature is logged to Rekor (public transparency log)
4. Attaches the CycloneDX SBOM as a **Cosign attestation** (stored alongside the image in GHCR)

After the pipeline runs, the job summary shows the exact `cosign verify` commands for your image.

### 5. Verify manually

```bash
# Set your image reference (copy the digest from the Actions job summary)
export IMAGE_REF="ghcr.io/your-org/supply-chain-sec/sample-app@sha256:<digest>"
export REPO="your-org/supply-chain-sec"

make verify IMAGE_REF=$IMAGE_REF REPO=$REPO
```

Or run the script directly:
```bash
bash scripts/verify.sh $IMAGE_REF $REPO
```

Expected output:
```
=== 1. Verifying image signature ===
{
  "subject": "https://github.com/your-org/supply-chain-sec/.github/workflows/build-sign-sbom.yml@refs/heads/main",
  "issuer": "https://token.actions.githubusercontent.com",
  "workflow": "refs/heads/main"
}

=== 2. Verifying SBOM attestation (CycloneDX) ===
{
  "sbomFormat": "https://cyclonedx.org/bom",
  "componentCount": 12,
  "timestamp": "2026-05-08T..."
}

=== 3. Checking Rekor transparency log entry ===
...
```

### How keyless signing works

```
GitHub Actions Job
      │
      ▼
GitHub OIDC Provider  ──► short-lived JWT (identity: workflow URL)
      │
      ▼
Fulcio CA  ──► issues x509 cert binding (workflow identity ↔ public key)
      │
      ▼
cosign sign  ──► signs image digest with ephemeral key pair
      │
      ▼
Rekor  ──► appends (cert + signature + digest) to immutable transparency log
```

No private keys to rotate or leak. The signature is verifiable by anyone using the issuer + identity, and is permanently recorded in Rekor.

---

## Repository Structure

```
.
├── apps/
│   └── sample-app/          # Phase 1 — Go HTTP service
│       ├── main.go
│       ├── go.mod
│       └── Dockerfile
├── services/
│   ├── sbom-ingester/       # Phase 2 — Go ingestion service (coming)
│   └── admission-webhook/   # Phase 3 — K8s admission webhook (coming)
├── dashboard/               # Phase 4 — React frontend (coming)
├── k8s/
│   └── kind-config.yaml     # Local cluster config
├── .github/
│   └── workflows/
│       └── build-sign-sbom.yml
├── scripts/
│   └── verify.sh
└── Makefile
```
