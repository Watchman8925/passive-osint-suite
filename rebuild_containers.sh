#!/bin/bash
# OSINT Suite Docker Rebuild Script
# This script helps rebuild the Docker containers with proper error handling

set -e

echo "🔧 OSINT Suite Docker Rebuild Script"
echo "===================================="

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    echo "Please install Docker first:"
    echo "  - Ubuntu/Debian: sudo apt-get install docker.io"
    echo "  - CentOS/RHEL: sudo yum install docker"
    echo "  - macOS: Install Docker Desktop"
    echo "  - Windows: Install Docker Desktop"
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ docker-compose is not available"
    echo "Please install docker-compose or use 'docker compose' (Docker CLI plugin)"
    exit 1
fi

echo "✅ Docker environment check passed"

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker-compose down || docker compose down || true

# Remove existing images to force rebuild
echo "🗑️  Removing existing images..."
docker-compose rm -f || docker compose rm -f || true
docker rmi osint-suite_osint-suite 2>/dev/null || true

# Clean up dangling images
echo "🧹 Cleaning up dangling images..."
docker image prune -f

# Rebuild containers
echo "🏗️  Rebuilding containers..."
if command -v docker-compose &> /dev/null; then
    docker-compose build --no-cache
    echo "✅ Build completed with docker-compose"
else
    docker compose build --no-cache
    echo "✅ Build completed with docker compose"
fi

# Start containers
echo "🚀 Starting containers..."
if command -v docker-compose &> /dev/null; then
    docker-compose up -d
    echo "✅ Containers started with docker-compose"
else
    docker compose up -d
    echo "✅ Containers started with docker compose"
fi

# Wait a bit for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check container status
echo "📊 Container status:"
if command -v docker-compose &> /dev/null; then
    docker-compose ps
else
    docker compose ps
fi

# Check logs for any immediate errors
echo "📋 Recent logs:"
if command -v docker-compose &> /dev/null; then
    docker-compose logs --tail=20 osint-suite
else
    docker compose logs --tail=20 osint-suite
fi

echo ""
echo "🎉 Rebuild completed!"
echo ""
echo "Services should be available at:"
echo "  - OSINT Suite API: http://localhost:8000"
echo "  - Prometheus: http://localhost:9090"
echo "  - Interactive menu: docker-compose exec osint-suite python osint_suite.py --quiet"
echo ""
echo "To view full logs: docker-compose logs -f"
echo "To stop services: docker-compose down"