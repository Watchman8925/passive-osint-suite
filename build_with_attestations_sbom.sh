#!/bin/bash
# Build Docker image with BuildKit provenance attestations, SBOM, and optional signing
set -e

REPO_URL="https://github.com/Watchman8925/passive-osint-suite"
GIT_COMMIT=$(git rev-parse HEAD)
IMAGE_NAME="passive-osint-suite:latest"

export DOCKER_BUILDKIT=1

docker build --attest=provenance=mode=max --attest=sbom=type=spdx \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  --build-arg GIT_REPO="$REPO_URL" \
  -t "$IMAGE_NAME" \
  -f Dockerfile .

# Optional: Docker image signing (requires Docker Content Trust setup)
# export DOCKER_CONTENT_TRUST=1
# docker push "$IMAGE_NAME"
