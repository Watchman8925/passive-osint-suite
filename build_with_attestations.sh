#!/bin/bash
# Build Docker image with BuildKit provenance attestations and supply chain labels
set -e

REPO_URL="https://github.com/Watchman8925/passive-osint-suite"
GIT_COMMIT=$(git rev-parse HEAD)

export DOCKER_BUILDKIT=1

docker build --attest=provenance=mode=max \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  --build-arg GIT_REPO="$REPO_URL" \
  -f Dockerfile .
