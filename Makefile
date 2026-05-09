REGISTRY   ?= ghcr.io
ORG        ?= Kumar-rahul18
IMAGE      := $(REGISTRY)/$(ORG)/supply-chain-sec/sample-app
VERSION    ?= dev
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
CLUSTER    := supply-chain-sec

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Local cluster ────────────────────────────────────────────────────────────

.PHONY: cluster-up
cluster-up: ## Create local kind cluster
	kind create cluster --config k8s/kind-config.yaml
	kubectl cluster-info --context kind-$(CLUSTER)

.PHONY: cluster-down
cluster-down: ## Delete local kind cluster
	kind delete cluster --name $(CLUSTER)

.PHONY: cluster-status
cluster-status: ## Show cluster node status
	kubectl get nodes -o wide

# ── Sample app ───────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build the sample-app Docker image locally
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		apps/sample-app

.PHONY: run
run: ## Run sample-app locally on port 8080
	docker run --rm -p 8080:8080 \
		-e PORT=8080 \
		$(IMAGE):latest

.PHONY: push
push: build ## Build and push image to registry
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

# ── SBOM & signing (local) ───────────────────────────────────────────────────

.PHONY: sbom
sbom: ## Generate SBOM for a local image (IMAGE_REF=... make sbom)
	@[ -n "$(IMAGE_REF)" ] || (echo "Usage: IMAGE_REF=<image>@<digest> make sbom" && exit 1)
	syft $(IMAGE_REF) \
		-o cyclonedx-json=sbom.cyclonedx.json \
		-o spdx-json=sbom.spdx.json
	@echo "Components: $$(jq '.components | length' sbom.cyclonedx.json)"

.PHONY: verify
verify: ## Verify signature + SBOM attestation (IMAGE_REF=... REPO=... make verify)
	@[ -n "$(IMAGE_REF)" ] || (echo "Usage: IMAGE_REF=<image>@<digest> REPO=org/repo make verify" && exit 1)
	@[ -n "$(REPO)" ]      || (echo "Usage: IMAGE_REF=<image>@<digest> REPO=org/repo make verify" && exit 1)
	bash scripts/verify.sh $(IMAGE_REF) $(REPO)

# ── Phase 2 — ingestion service ──────────────────────────────────────────────

.PHONY: stack-up
stack-up: ## Start Postgres + sbom-ingester via Docker Compose
	docker compose up --build -d
	@echo "Ingester: http://localhost:8080/health"

.PHONY: stack-down
stack-down: ## Stop and remove Docker Compose stack
	docker compose down -v

.PHONY: stack-logs
stack-logs: ## Tail ingestion service logs
	docker compose logs -f sbom-ingester

.PHONY: ingest
ingest: ## Ingest a local SBOM (SBOM=sbom.cyclonedx.json DIGEST=sha256:... NAME=... make ingest)
	@[ -n "$(SBOM)"   ] || (echo "Usage: SBOM=<file> DIGEST=<sha256:...> NAME=<image> make ingest" && exit 1)
	@[ -n "$(DIGEST)" ] || (echo "Usage: SBOM=<file> DIGEST=<sha256:...> NAME=<image> make ingest" && exit 1)
	bash scripts/ingest-sbom.sh $(SBOM) $(DIGEST) $(NAME) $(TAG)

# ── Tools installation check ─────────────────────────────────────────────────

.PHONY: check-tools
check-tools: ## Verify required tools are installed
	@echo "Checking required tools..."
	@command -v docker    && docker --version    || echo "MISSING: docker"
	@command -v kind      && kind version        || echo "MISSING: kind"
	@command -v kubectl   && kubectl version --client --short 2>/dev/null || echo "MISSING: kubectl"
	@command -v cosign    && cosign version      || echo "MISSING: cosign"
	@command -v syft      && syft version        || echo "MISSING: syft"
	@command -v grype     && grype version       || echo "MISSING: grype (needed for Phase 2)"
	@command -v helm      && helm version        || echo "MISSING: helm"
