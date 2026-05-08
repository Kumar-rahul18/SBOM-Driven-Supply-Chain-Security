#!/usr/bin/env bash
# Verify a signed image and its SBOM attestation from Rekor/Sigstore.
#
# Usage:
#   ./scripts/verify.sh <image-ref> <github-repo>
#
# Example:
#   ./scripts/verify.sh ghcr.io/your-org/supply-chain-sec/sample-app@sha256:abc123 your-org/supply-chain-sec

set -euo pipefail

IMAGE="${1:?Usage: verify.sh <image-ref> <github-repo>}"
REPO="${2:?Usage: verify.sh <image-ref> <github-repo>}"

CERT_IDENTITY="https://github.com/${REPO}/.*"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

echo ""
echo "=== 1. Verifying image signature ==="
cosign verify \
  --certificate-identity-regexp="${CERT_IDENTITY}" \
  --certificate-oidc-issuer="${OIDC_ISSUER}" \
  "${IMAGE}" | jq '.[0] | {subject: .critical.identity, issuer: .optional.Issuer, workflow: .optional.githubWorkflowRef}'

echo ""
echo "=== 2. Verifying SBOM attestation (CycloneDX) ==="
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp="${CERT_IDENTITY}" \
  --certificate-oidc-issuer="${OIDC_ISSUER}" \
  "${IMAGE}" | jq '.payload | @base64d | fromjson | {
    sbomFormat: .predicateType,
    componentCount: (.predicate.components | length),
    bomVersion: .predicate.metadata.version,
    timestamp: .predicate.metadata.timestamp
  }'

echo ""
echo "=== 3. Checking Rekor transparency log entry ==="
# Rekor stores a tamper-evident log entry for every signing event.
DIGEST=$(echo "${IMAGE}" | cut -d'@' -f2)
rekor-cli search --sha "${DIGEST}" 2>/dev/null || \
  echo "(Install rekor-cli to search the transparency log: https://docs.sigstore.dev/rekor/installation)"

echo ""
echo "Verification complete."
