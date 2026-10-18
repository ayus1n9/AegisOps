#!/usr/bin/env bash
# ==============================================================================
# AegisOps DevSecOps: Software Bill of Materials (SBOM) Generator
# Generates industry-standard CycloneDX and SPDX SBOMs using Syft.
# ==============================================================================
set -euo pipefail

OUTPUT_DIR="${1:-reports/sbom}"
mkdir -p "${OUTPUT_DIR}"

echo "[AegisOps SBOM] Generating CycloneDX SBOMs for application images..."

# Determine runner: local syft binary or docker containerized runner
if command -v syft >/dev/null 2>&1; then
    SYFT_CMD="syft"
else
    echo "[Info] 'syft' CLI not found locally. Using containerized runner (anchore/syft:latest)..."
    SYFT_CMD="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd)/${OUTPUT_DIR}:/out anchore/syft:v1.18.0"
fi

IMAGES=("aegisops/api:1.0.0" "aegisops/frontend:1.0.0" "aegisops/python-service:1.0.0")

for img in "${IMAGES[@]}"; do
    clean_name=$(echo "${img}" | tr '/:' '_')
    target_file="${OUTPUT_DIR}/${clean_name}.cyclonedx.json"
    echo "[AegisOps SBOM] Scanning ${img} -> ${target_file}"

    if command -v syft >/dev/null 2>&1; then
        syft "${img}" -o cyclonedx-json="${target_file}"
    else
        docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$(pwd)/${OUTPUT_DIR}:/out" \
            anchore/syft:v1.18.0 \
            "${img}" -o cyclonedx-json="/out/${clean_name}.cyclonedx.json"
    fi

    # Verify that SBOM was generated and contains valid JSON
    if [ -s "${target_file}" ] && jq empty "${target_file}" 2>/dev/null; then
        pkg_count=$(jq '.components | length' "${target_file}" 2>/dev/null || echo "N/A")
        echo "  ✓ Generated valid CycloneDX SBOM for ${img} (${pkg_count} components discovered)"
    else
        echo "  ✗ Warning: SBOM output missing or invalid for ${img}"
    fi
done

echo "[AegisOps SBOM] Generation complete. Files saved in ${OUTPUT_DIR}/"
