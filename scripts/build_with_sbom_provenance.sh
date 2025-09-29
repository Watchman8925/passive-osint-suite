#!/usr/bin/env bash
set -euo pipefail

# Build and push with SBOM + provenance attestations using Docker Buildx
# Requirements: Docker Buildx (v0.12+), logged in to Docker Hub
# Usage: ./scripts/build_with_sbom_provenance.sh watchman89/passive-osint-suite:latest

IMAGE_TAG="${1:-watchman89/passive-osint-suite:latest}"

# Ensure buildx is available
if ! docker buildx version >/dev/null 2>&1; then
  echo "Docker buildx is required. Install via 'docker buildx install' or Docker Desktop." >&2
  exit 1
fi

# Create builder if missing
if ! docker buildx inspect osintbuilder >/dev/null 2>&1; then
  docker buildx create --name osintbuilder --use
fi

# Build and push with SBOM + provenance
DOCKER_BUILDKIT=1 docker buildx build \
  --push \
  --provenance=mode=max \
  --sbom=true \
  --platform linux/amd64 \
  -t "$IMAGE_TAG" \
  .

echo "Build complete with SBOM and provenance for $IMAGE_TAG"
