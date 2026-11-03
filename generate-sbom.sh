#!/bin/bash
set -euo pipefail

IMAGE_NAME="${1:-help-im-vulnerable}"
SBOM_NAME="${2:-Help-Im-Vulnerable}"
SBOM_VERSION="${3:-1.0.0}"
OUTPUT="${4:-sbom.json}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1: Build container image ==="
podman build -f Containerfile -t "$IMAGE_NAME" .

echo ""
echo "=== Step 2: Extract Maven SBOM from image ==="
CONTAINER_ID=$(podman create "$IMAGE_NAME")
podman cp "$CONTAINER_ID:/deployments/maven-sbom.json" /tmp/maven-sbom.json
podman rm "$CONTAINER_ID" > /dev/null
echo "Extracted /tmp/maven-sbom.json"

echo ""
echo "=== Step 3: Generate container SBOM with syft ==="
podman save "$IMAGE_NAME" --format oci-archive -o /tmp/help-im-vulnerable.tar
syft /tmp/help-im-vulnerable.tar \
  -o cyclonedx-json@1.6 \
  --source-name "$SBOM_NAME" \
  --source-version "$SBOM_VERSION" \
  > /tmp/syft-sbom.json
echo "Generated /tmp/syft-sbom.json"

echo ""
echo "=== Step 4: Merge SBOMs (Maven deps + OS/runtime) ==="
python3 "$SCRIPT_DIR/merge-sboms.py" \
  /tmp/maven-sbom.json \
  /tmp/syft-sbom.json \
  "$SCRIPT_DIR/$OUTPUT"

echo ""
echo "=== Done ==="
echo "SBOM: $OUTPUT"

rm -f /tmp/maven-sbom.json /tmp/syft-sbom.json /tmp/help-im-vulnerable.tar
