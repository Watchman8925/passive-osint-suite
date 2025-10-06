#!/bin/bash
# Fast lightweight build script for CI/CD

set -euo pipefail

echo "Building lightweight OSINT Suite image..."

# Get git metadata
GIT_COMMIT=$(git rev-parse HEAD)
GIT_REPO="https://github.com/Watchman8925/passive-osint-suite"

# Build with optimizations for CI
docker build \
  --attest=provenance=mode=max \
  --attest=sbom=type=spdx \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  --build-arg GIT_REPO="$GIT_REPO" \
  --progress=plain \
  --no-cache \
  -t watchman8925/passive-osint-suite:lite \
  -f Dockerfile.lite \
  .

echo "✅ Lightweight build completed successfully!"
echo "Image size:"
docker images watchman8925/passive-osint-suite:lite --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"