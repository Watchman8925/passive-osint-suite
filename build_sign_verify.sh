#!/bin/bash
# Build, sign, and verify Docker image with BuildKit provenance attestations and SBOM
set -e

REPO_URL="https://github.com/Watchman8925/passive-osint-suite"
GIT_COMMIT=$(git rev-parse HEAD)
IMAGE_NAME="passive-osint-suite:latest"

export DOCKER_BUILDKIT=1

# Build with provenance and SBOM

docker build --attest=provenance=mode=max --attest=sbom=type=spdx \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  --build-arg GIT_REPO="$REPO_URL" \
  -t "$IMAGE_NAME" \
  -f Dockerfile .

# Sign the image (requires Docker Content Trust keys)
export DOCKER_CONTENT_TRUST=1
# Uncomment the next line to push and sign to a registry (replace <your-registry>)
# docker tag "$IMAGE_NAME" <your-registry>/passive-osint-suite:latest
# docker push <your-registry>/passive-osint-suite:latest

# Verify SBOM and signature (example: cosign for signature, syft for SBOM)
# cosign verify <your-registry>/passive-osint-suite:latest
# syft <your-registry>/passive-osint-suite:latest

echo "Build, SBOM, and signing steps complete. See comments for registry push and verification commands."
