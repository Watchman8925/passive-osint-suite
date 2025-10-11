#!/bin/bash
# Quick Install Script for Passive OSINT Suite
# One-command installation and startup

set -e

echo "🚀 Passive OSINT Suite - Quick Install"
echo "======================================"
echo ""

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if Docker is available
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    print_info "Docker detected - Using containerized deployment"
    USE_DOCKER=true
else
    print_info "Docker not found - Using local installation"
    USE_DOCKER=false
fi

# Step 1: Setup environment
print_info "Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    print_success "Created .env file"
    
    # Generate secure keys
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    
    # Update .env with generated keys
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/OSINT_SECRET_KEY=.*/OSINT_SECRET_KEY=$SECRET_KEY/" .env
        sed -i '' "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/" .env
    else
        sed -i "s/OSINT_SECRET_KEY=.*/OSINT_SECRET_KEY=$SECRET_KEY/" .env
        sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/" .env
    fi
    
    print_success "Generated secure keys"
else
    print_success ".env file already exists"
fi

if [ "$USE_DOCKER" = true ]; then
    # Docker installation
    print_info "Starting services with Docker..."
    
    # Build and start services
    docker-compose up -d --build
    
    print_success "Docker services started"
    
    # Wait for services to be ready
    print_info "Waiting for services to be ready..."
    sleep 10
    
    # Check health
    if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        print_success "API server is running"
    else
        print_error "API server may not be ready yet - check logs with: docker-compose logs"
    fi
    
else
    # Local installation
    print_info "Installing dependencies..."
    
    # Check Python version
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    REQUIRED_VERSION="3.10"
    
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
        print_error "Python 3.10+ required (found $PYTHON_VERSION)"
        exit 1
    fi
    
    print_success "Python version check passed"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Created virtual environment"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install minimal requirements first
    print_info "Installing core dependencies..."
    pip install -q --upgrade pip setuptools wheel
    
    # Install only essential packages for quick start
    pip install -q fastapi uvicorn requests beautifulsoup4 rich colorama
    
    print_success "Core dependencies installed"
    
    # Start API server in background
    print_info "Starting API server..."
    python3 api/api_server.py &
    API_PID=$!
    
    sleep 5
    
    # Check if API is running
    if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        print_success "API server started (PID: $API_PID)"
    else
        print_error "API server failed to start - check logs"
    fi
fi

echo ""
echo "======================================"
print_success "Installation complete!"
echo ""
echo "Access the suite:"
echo "  • API Documentation: http://localhost:8000/docs"
echo "  • Health Check: http://localhost:8000/api/health"
echo ""

if [ "$USE_DOCKER" = true ]; then
    echo "Useful commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Stop services: docker-compose down"
    echo "  • Restart: docker-compose restart"
else
    echo "To stop the API server:"
    echo "  kill $API_PID"
    echo ""
    echo "To start web interface:"
    echo "  cd web && npm install && npm run dev"
fi

echo ""
echo "For full installation with all features:"
echo "  ./install_universal.sh"
echo ""
