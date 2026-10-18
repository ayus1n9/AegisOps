#!/usr/bin/env bash
# ==============================================================================
# AegisOps DevSecOps: Container Image & Artifact Signing with Cosign
# Demonstrates verifiable cryptographic signing and verification.
# ==============================================================================
set -euo pipefail

KEY_DIR="reports/signing"
mkdir -p "${KEY_DIR}"
COSIGN_KEY="${KEY_DIR}/cosign.key"
COSIGN_PUB="${KEY_DIR}/cosign.pub"

echo "[AegisOps Signing] Setting up artifact signature workflow..."

# Check if cosign is available or run via docker
if command -v cosign >/dev/null 2>&1; then
    COSIGN_CMD="cosign"
else
    echo "[Info] 'cosign' CLI not found locally. Using containerized runner (sigstore/cosign:latest)..."
    COSIGN_CMD="docker run --rm -v $(pwd):/workspace -w /workspace sigstore/cosign:v2.4.1"
fi

# Generate ephemeral key pair for local demonstration (password empty for automated CI/local test)
if [ ! -f "${COSIGN_PUB}" ]; then
    echo "[AegisOps Signing] Generating local key pair..."
    export COSIGN_PASSWORD=""
    if command -v cosign >/dev/null 2>&1; then
        cosign generate-key-pair --output-key-prefix "${KEY_DIR}/cosign"
    else
        docker run --rm -e COSIGN_PASSWORD="" -v "$(pwd):/workspace" -w /workspace sigstore/cosign:v2.4.1 \
            generate-key-pair --output-key-prefix "${KEY_DIR}/cosign"
    fi
    echo "  ✓ Generated test public key at ${COSIGN_PUB}"
fi

# Create cryptographic digest payload to demonstrate signature verification
TARGET_PAYLOAD="${KEY_DIR}/release_manifest.json"
cat << 'JSON' > "${TARGET_PAYLOAD}"
{
  "project": "aegisops",
  "version": "1.0.0",
  "images": [
    "aegisops/api:1.0.0",
    "aegisops/frontend:1.0.0",
    "aegisops/python-service:1.0.0"
  ],
  "policy": "passed",
  "timestamp": "2026-10-18T10:00:00Z"
}
JSON

SIGNATURE_FILE="${KEY_DIR}/manifest.sig"

echo "[AegisOps Signing] Signing release manifest payload..."
if command -v cosign >/dev/null 2>&1; then
    export COSIGN_PASSWORD=""
    cosign sign-blob --key "${COSIGN_KEY}" --tlog-upload=false "${TARGET_PAYLOAD}" > "${SIGNATURE_FILE}"
    echo "[AegisOps Signing] Verifying signature against public key..."
    cosign verify-blob --key "${COSIGN_PUB}" --signature "${SIGNATURE_FILE}" "${TARGET_PAYLOAD}"
else
    docker run --rm -e COSIGN_PASSWORD="" -v "$(pwd):/workspace" -w /workspace sigstore/cosign:v2.4.1 \
        sign-blob --key "${COSIGN_KEY}" --tlog-upload=false "${TARGET_PAYLOAD}" > "${SIGNATURE_FILE}"
    echo "[AegisOps Signing] Verifying signature against public key..."
    docker run --rm -v "$(pwd):/workspace" -w /workspace sigstore/cosign:v2.4.1 \
        verify-blob --key "${COSIGN_PUB}" --signature "${SIGNATURE_FILE}" "${TARGET_PAYLOAD}"
fi

echo "  ✓ Artifact signature verified successfully against public key!"
echo "[AegisOps Signing] Signature verification complete."
