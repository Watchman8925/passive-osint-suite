#!/bin/bash

# Docker Quick Deploy Script for Passive OSINT Suite
# This script handles complete Docker deployment with minimal user input

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check available memory
    available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [ "$available_memory" -lt 4000 ]; then
        print_warning "Available memory is less than 4GB. Performance may be impacted."
    fi
    
    # Check disk space
    available_space=$(df . | awk 'NR==2{printf "%.0f", $4/1024/1024}')
    if [ "$available_space" -lt 10 ]; then
        print_warning "Available disk space is less than 10GB. May not be sufficient."
    fi
    
    print_success "Prerequisites check completed"
}

# Function to setup environment
setup_environment() {
    print_status "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            print_success "Environment file created from template"
        else
            print_error ".env.example not found. Creating minimal environment..."
            cat > .env << EOF
# Minimal OSINT Suite Configuration
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
OSINT_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")

# Database
POSTGRES_DB=osint_audit
POSTGRES_USER=osint_user

# API Settings
API_HOST=0.0.0.0
API_PORT=8000
API_CORS_ORIGINS=["http://localhost:3000","http://localhost:8000"]

# LLM Configuration
LLM_MODEL_CACHE_DIR=/app/models
LLM_USE_CACHE=true
HF_HOME=/app/models

# Logging
LOG_LEVEL=INFO
LOG_FILE_MAX_SIZE=100MB
LOG_BACKUP_COUNT=5

# Security
ENABLE_AUDIT_LOGGING=true
AUDIT_LOG_RETENTION_DAYS=365
EOF
        fi
    else
        print_success "Environment file already exists"
    fi
    
    # Generate secure keys if they don't exist
    if ! grep -q "SECRET_KEY=" .env || [ "$(grep SECRET_KEY= .env | cut -d'=' -f2)" = "" ]; then
        print_status "Generating secure keys..."
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        OSINT_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
        
        # Update .env file
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
        sed -i "s/OSINT_MASTER_KEY=.*/OSINT_MASTER_KEY=$OSINT_MASTER_KEY/" .env
        sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET_KEY/" .env
        sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
        
        print_success "Secure keys generated and updated"
    fi
}

# Function to build Docker images
build_images() {
    print_status "Building Docker images..."
    
    # Build with progress and no cache for clean build
    if docker-compose build --no-cache --progress=plain; then
        print_success "Docker images built successfully"
    else
        print_error "Failed to build Docker images"
        exit 1
    fi
}

# Function to start services
start_services() {
    print_status "Starting OSINT Suite services..."
    
    # Start services in background
    if docker-compose up -d; then
        print_success "Services started successfully"
    else
        print_error "Failed to start services"
        exit 1
    fi
    
    # Wait for services to be ready
    print_status "Waiting for services to initialize..."
    sleep 10
    
    # Check service health
    max_attempts=30
    attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            print_success "OSINT Suite is ready!"
            break
        fi
        
        attempt=$((attempt + 1))
        print_status "Waiting for OSINT Suite to be ready... (attempt $attempt/$max_attempts)"
        sleep 5
    done
    
    if [ $attempt -eq $max_attempts ]; then
        print_warning "OSINT Suite may not be fully ready. Check logs with: docker-compose logs osint-suite"
    fi
}

# Function to verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Check container status
    print_status "Container status:"
    docker-compose ps
    
    # Check module availability
    print_status "Checking analysis modules..."
    if docker exec osint-suite python -c "
from modules import MODULE_REGISTRY
total = len(MODULE_REGISTRY)
analysis_modules = ['bellingcat_toolkit', 'blackbox_patterns', 'conspiracy_analyzer', 'cross_reference_engine', 'hidden_pattern_detector']
found = [m for m in analysis_modules if m in MODULE_REGISTRY]
print(f'Total modules loaded: {total}')
print(f'Specialized analysis modules: {len(found)}/5')
if len(found) == 5:
    print('✓ All specialized analysis modules loaded successfully')
else:
    print('⚠ Some analysis modules may not be loaded properly')
    print(f'Missing: {[m for m in analysis_modules if m not in MODULE_REGISTRY]}')
" 2>/dev/null; then
        print_success "Module verification completed"
    else
        print_warning "Module verification failed. Check logs for details."
    fi
    
    # Test API endpoints
    print_status "Testing API endpoints..."
    
    if curl -s http://localhost:8000/health | grep -q "healthy"; then
        print_success "✓ Health check endpoint working"
    else
        print_warning "⚠ Health check endpoint may have issues"
    fi
    
    if curl -s http://localhost:8000/modules | grep -q "modules"; then
        print_success "✓ Modules endpoint working"
    else
        print_warning "⚠ Modules endpoint may have issues"
    fi
}

# Function to show access information
show_access_info() {
    print_success "🚀 OSINT Suite deployment completed!"
    echo
    echo -e "${GREEN}Access Information:${NC}"
    echo -e "  📊 Main API: ${BLUE}http://localhost:8000${NC}"
    echo -e "  📚 API Documentation: ${BLUE}http://localhost:8000/docs${NC}"
    echo -e "  ❤️  Health Check: ${BLUE}http://localhost:8000/health${NC}"
    echo -e "  📈 Grafana Dashboard: ${BLUE}http://localhost:3000${NC} (admin/admin123)"
    echo -e "  📊 Prometheus Metrics: ${BLUE}http://localhost:9090${NC}"
    echo
    echo -e "${GREEN}Quick Commands:${NC}"
    echo -e "  📋 View logs: ${YELLOW}docker-compose logs -f osint-suite${NC}"
    echo -e "  🔍 Check status: ${YELLOW}docker-compose ps${NC}"
    echo -e "  🛑 Stop services: ${YELLOW}docker-compose down${NC}"
    echo -e "  🔄 Restart: ${YELLOW}docker-compose restart osint-suite${NC}"
    echo
    echo -e "${GREEN}Usage Examples:${NC}"
    echo -e "  🌐 Domain analysis: ${YELLOW}curl -X POST http://localhost:8000/analyze -H 'Content-Type: application/json' -d '{\"target\":\"example.com\",\"modules\":[\"whois\",\"dns\"]}'${NC}"
    echo -e "  🔧 CLI access: ${YELLOW}docker exec -it osint-suite bash${NC}"
    echo
}

# Function to show troubleshooting info
show_troubleshooting() {
    if [ "$1" = "error" ]; then
        echo -e "${RED}Deployment encountered issues. Troubleshooting steps:${NC}"
    else
        echo -e "${YELLOW}Troubleshooting Information:${NC}"
    fi
    
    echo -e "  🔍 Check logs: ${YELLOW}docker-compose logs osint-suite${NC}"
    echo -e "  🔧 Rebuild: ${YELLOW}docker-compose build --no-cache && docker-compose up -d${NC}"
    echo -e "  📊 Resource usage: ${YELLOW}docker stats${NC}"
    echo -e "  🗂️  Check environment: ${YELLOW}cat .env${NC}"
    echo -e "  🧹 Clean up: ${YELLOW}docker system prune -f${NC}"
    echo
}

# Main deployment function
main() {
    echo -e "${BLUE}🔍 Passive OSINT Suite - Docker Quick Deploy${NC}"
    echo -e "${BLUE}==========================================${NC}"
    echo
    
    # Trap to show troubleshooting on error
    trap 'show_troubleshooting error' ERR
    
    check_prerequisites
    setup_environment
    build_images
    start_services
    verify_deployment
    show_access_info
    show_troubleshooting
    
    print_success "Deployment completed successfully! 🎉"
}

# Parse command line arguments
case "${1:-}" in
    "--help"|"-h")
        echo "Docker Quick Deploy Script for Passive OSINT Suite"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --no-build     Skip building images (use existing)"
        echo "  --check        Only check prerequisites"
        echo "  --logs         Show logs after deployment"
        echo
        exit 0
        ;;
    "--check")
        check_prerequisites
        exit 0
        ;;
    "--no-build")
        echo -e "${BLUE}🔍 Passive OSINT Suite - Quick Start (No Build)${NC}"
        check_prerequisites
        setup_environment
        start_services
        verify_deployment
        show_access_info
        ;;
    "--logs")
        main
        echo -e "\n${BLUE}Following logs (Ctrl+C to exit):${NC}"
        docker-compose logs -f osint-suite
        ;;
    *)
        main
        ;;
esac