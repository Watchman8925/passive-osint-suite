#!/bin/bash
# Docker Image Security Scanner
# This script runs comprehensive security scans on the Docker image

set -euo pipefail

IMAGE_NAME="${1:-passive-osint-suite:latest}"
SCAN_DIR="${2:-.security-scan}"

echo "==================================="
echo "Docker Image Security Scanner"
echo "==================================="
echo "Image: $IMAGE_NAME"
echo "Output directory: $SCAN_DIR"
echo ""

# Create output directory
mkdir -p "$SCAN_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. Hadolint - Dockerfile linting
echo "[1/5] Running Hadolint (Dockerfile linting)..."
if command_exists hadolint; then
    hadolint Dockerfile > "$SCAN_DIR/hadolint-report.txt" 2>&1 || echo "Hadolint found issues (see report)"
    echo "✓ Hadolint scan complete"
else
    echo "⚠ Hadolint not installed. Running via Docker..."
    docker run --rm -i hadolint/hadolint < Dockerfile > "$SCAN_DIR/hadolint-report.txt" 2>&1 || echo "Hadolint found issues (see report)"
    echo "✓ Hadolint scan complete"
fi
echo ""

# 2. Trivy - Vulnerability scanning
echo "[2/5] Running Trivy (vulnerability scanning)..."
if command_exists trivy; then
    trivy image --severity HIGH,CRITICAL \
        --format json \
        --output "$SCAN_DIR/trivy-report.json" \
        "$IMAGE_NAME" || echo "⚠ Trivy found vulnerabilities"
    
    trivy image --severity HIGH,CRITICAL \
        --format table \
        "$IMAGE_NAME" > "$SCAN_DIR/trivy-report.txt" || echo "⚠ Trivy found vulnerabilities"
    
    echo "✓ Trivy scan complete"
else
    echo "⚠ Trivy not installed. Running via Docker..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest image --severity HIGH,CRITICAL \
        --format table \
        "$IMAGE_NAME" > "$SCAN_DIR/trivy-report.txt" 2>&1 || echo "⚠ Trivy found vulnerabilities"
    echo "✓ Trivy scan complete"
fi
echo ""

# 3. Dockle - Docker image linting
echo "[3/5] Running Dockle (best practices check)..."
if command_exists dockle; then
    dockle --format json --output "$SCAN_DIR/dockle-report.json" "$IMAGE_NAME" || echo "⚠ Dockle found issues"
    dockle "$IMAGE_NAME" > "$SCAN_DIR/dockle-report.txt" 2>&1 || echo "⚠ Dockle found issues"
    echo "✓ Dockle scan complete"
else
    echo "⚠ Dockle not installed. Running via Docker..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        goodwithtech/dockle:latest "$IMAGE_NAME" > "$SCAN_DIR/dockle-report.txt" 2>&1 || echo "⚠ Dockle found issues"
    echo "✓ Dockle scan complete"
fi
echo ""

# 4. Docker Scout (if available)
echo "[4/5] Running Docker Scout (if available)..."
if docker scout version >/dev/null 2>&1; then
    docker scout cves --format table "$IMAGE_NAME" > "$SCAN_DIR/docker-scout-report.txt" 2>&1 || echo "⚠ Docker Scout found issues"
    echo "✓ Docker Scout scan complete"
else
    echo "⚠ Docker Scout not available, skipping"
fi
echo ""

# 5. Image analysis
echo "[5/5] Running image analysis..."
{
    echo "==================================="
    echo "Docker Image Analysis"
    echo "==================================="
    echo ""
    
    echo "Image Details:"
    docker inspect "$IMAGE_NAME" --format='
    Repository: {{.RepoTags}}
    Created: {{.Created}}
    Size: {{.Size}} bytes
    Architecture: {{.Architecture}}
    OS: {{.Os}}
    ' || echo "Could not inspect image"
    
    echo ""
    echo "Image History (layers):"
    docker history --no-trunc "$IMAGE_NAME" || echo "Could not get history"
    
    echo ""
    echo "==================================="
} > "$SCAN_DIR/image-analysis.txt"
echo "✓ Image analysis complete"
echo ""

# Generate summary report
echo "==================================="
echo "Generating Summary Report"
echo "==================================="

{
    echo "Docker Image Security Scan Summary"
    echo "=================================="
    echo "Image: $IMAGE_NAME"
    echo "Scan Date: $(date)"
    echo "Scan Directory: $SCAN_DIR"
    echo ""
    
    echo "## Scan Results"
    echo ""
    
    if [ -f "$SCAN_DIR/hadolint-report.txt" ]; then
        echo "### Hadolint (Dockerfile Linting)"
        echo "See: $SCAN_DIR/hadolint-report.txt"
        echo ""
    fi
    
    if [ -f "$SCAN_DIR/trivy-report.txt" ]; then
        echo "### Trivy (Vulnerability Scanning)"
        echo "See: $SCAN_DIR/trivy-report.txt"
        echo ""
    fi
    
    if [ -f "$SCAN_DIR/dockle-report.txt" ]; then
        echo "### Dockle (Best Practices)"
        echo "See: $SCAN_DIR/dockle-report.txt"
        echo ""
    fi
    
    if [ -f "$SCAN_DIR/docker-scout-report.txt" ]; then
        echo "### Docker Scout"
        echo "See: $SCAN_DIR/docker-scout-report.txt"
        echo ""
    fi
    
    echo "### Image Analysis"
    echo "See: $SCAN_DIR/image-analysis.txt"
    echo ""
    
    echo "## Recommendations"
    echo ""
    echo "1. Review all HIGH and CRITICAL vulnerabilities in Trivy report"
    echo "2. Address any security issues identified by Dockle"
    echo "3. Update base image regularly to get security patches"
    echo "4. Keep dependencies up to date"
    echo "5. Review and minimize installed packages"
    echo ""
} > "$SCAN_DIR/SUMMARY.txt"

cat "$SCAN_DIR/SUMMARY.txt"

echo ""
echo "==================================="
echo "Scan Complete!"
echo "==================================="
echo "Results saved to: $SCAN_DIR/"
echo ""
echo "Review the following files:"
echo "  - $SCAN_DIR/SUMMARY.txt"
echo "  - $SCAN_DIR/trivy-report.txt"
echo "  - $SCAN_DIR/dockle-report.txt"
echo "  - $SCAN_DIR/hadolint-report.txt"
echo ""
