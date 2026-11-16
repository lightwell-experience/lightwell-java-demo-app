#!/bin/bash
set -euo pipefail

IMAGE_NAME="${1:-help-im-vulnerable}"
SBOM_NAME="${2:-Help-Im-Vulnerable}"
SBOM_VERSION="${3:-1.0.0}"
OUTPUT="${4:-sbom.json}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Use the caller's standard temporary directory rather than /tmp directly.
# macOS normally sets TMPDIR to a private per-user directory; /tmp is the
# conventional fallback when TMPDIR is unset.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lightwell-sbom.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
MAVEN_SBOM="$WORK_DIR/maven-sbom.json"
IMAGE_ARCHIVE="$WORK_DIR/help-im-vulnerable.tar"
SYFT_SBOM="$WORK_DIR/syft-sbom.json"

echo "=== Step 1: Build container image ==="
podman build -f Containerfile -t "$IMAGE_NAME" .

echo ""
echo "=== Step 2: Extract Maven SBOM from image ==="
CONTAINER_ID=$(podman create "$IMAGE_NAME")
podman cp "$CONTAINER_ID:/deployments/maven-sbom.json" "$MAVEN_SBOM"
podman rm "$CONTAINER_ID" > /dev/null
echo "Extracted Maven SBOM"

echo ""
echo "=== Step 3: Generate container SBOM with syft ==="
podman save "$IMAGE_NAME" --format oci-archive -o "$IMAGE_ARCHIVE"
syft "$IMAGE_ARCHIVE" \
  -o cyclonedx-json@1.6 \
  --source-name "$SBOM_NAME" \
  --source-version "$SBOM_VERSION" \
  > "$SYFT_SBOM"
echo "Generated container SBOM"

echo ""
echo "=== Step 4: Merge SBOMs (Maven deps + OS/runtime) ==="
python3 "$SCRIPT_DIR/merge-sboms.py" \
  "$MAVEN_SBOM" \
  "$SYFT_SBOM" \
  "$SCRIPT_DIR/$OUTPUT"

echo ""
echo "=== Done ==="
echo "SBOM: $OUTPUT"
