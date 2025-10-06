#!/bin/bash
# Build, sign, push, and verify Docker image with full supply chain compliance
set -e

REPO_URL="https://github.com/Watchman8925/passive-osint-suite"
GIT_COMMIT=$(git rev-parse HEAD)
IMAGE_NAME="passive-osint-suite:latest"
REGISTRY_IMAGE="docker.io/watchman8925/passive-osint-suite:latest"

export DOCKER_BUILDKIT=1
export DOCKER_CONTENT_TRUST=1

# Build with provenance and SBOM

docker build --attest=provenance=mode=max --attest=sbom=type=spdx \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  --build-arg GIT_REPO="$REPO_URL" \
  -t "$IMAGE_NAME" \
  -f Dockerfile .

# Tag and push (signed)
docker tag "$IMAGE_NAME" "$REGISTRY_IMAGE"
docker push "$REGISTRY_IMAGE"

# Verify signature (Docker Content Trust)
docker trust inspect --pretty "$REGISTRY_IMAGE"

# Verify SBOM (syft)
~/.local/bin/syft "$REGISTRY_IMAGE"

echo "Build, signing, push, and verification complete."
