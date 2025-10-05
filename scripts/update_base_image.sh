#!/bin/bash
# Script to update the Docker base image digest
# This ensures the Dockerfile uses the latest secure base image

set -euo pipefail

BASE_IMAGE="python:3.12-slim"
DOCKERFILE="Dockerfile"

echo "==================================="
echo "Docker Base Image Update Tool"
echo "==================================="
echo ""

# Pull the latest version
echo "[1/4] Pulling latest $BASE_IMAGE..."
docker pull "$BASE_IMAGE"
echo ""

# Get the digest
echo "[2/4] Getting image digest..."
DIGEST=$(docker inspect "$BASE_IMAGE" --format='{{index .RepoDigests 0}}' | cut -d'@' -f2)
FULL_IMAGE_REF="${BASE_IMAGE}@${DIGEST}"

echo "Current digest: $DIGEST"
echo "Full reference: $FULL_IMAGE_REF"
echo ""

# Backup the Dockerfile
echo "[3/4] Backing up Dockerfile..."
cp "$DOCKERFILE" "${DOCKERFILE}.backup"
echo "Backup created: ${DOCKERFILE}.backup"
echo ""

# Update the Dockerfile
echo "[4/4] Updating Dockerfile..."

# Find and replace the base image references
# We need to update both the builder and production stages
OLD_PATTERN="FROM python:3.12-slim@sha256:[a-f0-9]* AS"
NEW_BUILDER="FROM ${FULL_IMAGE_REF} AS builder"
NEW_PRODUCTION="FROM ${FULL_IMAGE_REF} AS production"

# Use sed to update both occurrences
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s|FROM python:3.12-slim@sha256:[a-f0-9]* AS builder|${NEW_BUILDER}|g" "$DOCKERFILE"
    sed -i '' "s|FROM python:3.12-slim@sha256:[a-f0-9]* AS production|${NEW_PRODUCTION}|g" "$DOCKERFILE"
else
    # Linux
    sed -i "s|FROM python:3.12-slim@sha256:[a-f0-9]* AS builder|${NEW_BUILDER}|g" "$DOCKERFILE"
    sed -i "s|FROM python:3.12-slim@sha256:[a-f0-9]* AS production|${NEW_PRODUCTION}|g" "$DOCKERFILE"
fi

echo "✓ Dockerfile updated successfully"
echo ""

# Show the changes
echo "==================================="
echo "Changes Made:"
echo "==================================="
grep "FROM python" "$DOCKERFILE" || echo "Could not verify changes"
echo ""

# Verify the Dockerfile syntax
echo "==================================="
echo "Verifying Dockerfile Syntax..."
echo "==================================="
docker run --rm -i hadolint/hadolint < "$DOCKERFILE" || echo "⚠ Hadolint found issues (check output above)"
echo ""

echo "==================================="
echo "Update Complete!"
echo "==================================="
echo ""
echo "Next steps:"
echo "1. Review the changes: git diff $DOCKERFILE"
echo "2. Test build: docker build -t test-image:latest ."
echo "3. Run security scan: ./scripts/scan_docker_image.sh test-image:latest"
echo "4. If all looks good, commit the changes"
echo "5. If something went wrong, restore backup: mv ${DOCKERFILE}.backup $DOCKERFILE"
echo ""
