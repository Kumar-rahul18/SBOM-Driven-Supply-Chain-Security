#!/usr/bin/env bash
# Manually post a CycloneDX SBOM to the ingestion service.
#
# Usage:
#   ./scripts/ingest-sbom.sh <sbom-file> <image-digest> [image-name] [image-tag] [signed]
#
# Example:
#   ./scripts/ingest-sbom.sh sbom.cyclonedx.json \
#     sha256:ff39d58722b445c99817861d0f8da4a3f0744b75002f78ab9f7b7ccbc1874d58 \
#     ghcr.io/kumar-rahul18/sbom-driven-supply-chain-security/sample-app \
#     latest \
#     true

set -euo pipefail

SBOM_FILE="${1:?Usage: ingest-sbom.sh <sbom-file> <digest> [name] [tag] [signed]}"
DIGEST="${2:?Usage: ingest-sbom.sh <sbom-file> <digest> [name] [tag] [signed]}"
IMAGE_NAME="${3:-}"
IMAGE_TAG="${4:-latest}"
SIGNED="${5:-false}"
INGEST_URL="${INGEST_URL:-http://localhost:8080}"

if [ ! -f "$SBOM_FILE" ]; then
  echo "Error: SBOM file not found: $SBOM_FILE" >&2
  exit 1
fi

echo "Posting SBOM to ${INGEST_URL}/ingest ..."

RESPONSE=$(curl -sf -X POST "${INGEST_URL}/ingest" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
        --arg name   "$IMAGE_NAME" \
        --arg tag    "$IMAGE_TAG" \
        --arg digest "$DIGEST" \
        --arg signed "$SIGNED" \
        --slurpfile sbom "$SBOM_FILE" \
        '{
          image_name:   $name,
          image_tag:    $tag,
          image_digest: $digest,
          registry:     ($name | split("/")[0]),
          signed:       ($signed == "true"),
          sbom:         $sbom[0]
        }')")

echo "$RESPONSE" | jq .
