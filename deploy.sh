#!/bin/bash
#!/bin/bash

# Advanced OSINT Suite - Complete Deployment Script
# ================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}========================================${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "🚀 Starting Advanced OSINT Suite deployment..."

# Check if Python is installed

set -euo pipefail

# Configuration
ENVIRONMENT=${1:-staging}
VERSION=${2:-latest}
NAMESPACE="osint-${ENVIRONMENT}"
REGISTRY="ghcr.io/watchman8925/passive_osint_suite"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Validate environment
validate_environment() {
    log "Validating environment: ${ENVIRONMENT}"
    
    case ${ENVIRONMENT} in
        development|staging|production)
            log "Environment ${ENVIRONMENT} is valid"
            ;;
        *)
            error "Invalid environment: ${ENVIRONMENT}. Must be development, staging, or production"
            ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed or not in PATH"
    fi
    
    # Check if docker is available
    if ! command -v docker &> /dev/null; then
        error "docker is not installed or not in PATH"
    fi
    
    # Check if helm is available (if using Helm)
    if ! command -v helm &> /dev/null; then
        warning "helm is not installed - using kubectl instead"
    fi
    
    success "Prerequisites check passed"
}

# Generate secrets
generate_secrets() {
    log "Generating secrets for ${ENVIRONMENT}..."
    
    # Generate master key for encryption
    MASTER_KEY=$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
    
    # Create Kubernetes secret
    kubectl create secret generic osint-secrets \
        --namespace=${NAMESPACE} \
        --from-literal=master-key="${MASTER_KEY}" \
        --from-literal=postgres-password="$(openssl rand -base64 32)" \
        --from-literal=grafana-password="$(openssl rand -base64 16)" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    success "Secrets generated and applied"
}

# Deploy infrastructure
deploy_infrastructure() {
    log "Deploying infrastructure for ${ENVIRONMENT}..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy using docker-compose (for development) or Kubernetes (for staging/production)
    if [[ ${ENVIRONMENT} == "development" ]]; then
        deploy_with_compose
    else
        deploy_with_kubernetes
    fi
}

# Deploy with Docker Compose (development)
deploy_with_compose() {
    log "Deploying with Docker Compose for development..."
    
    # Set environment variables
    export OSINT_MASTER_KEY="${MASTER_KEY}"
    export POSTGRES_PASSWORD="development_password"
    export GRAFANA_PASSWORD="admin123"
    
    # Build and deploy
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
    
    success "Development environment deployed"
}

# Deploy with Kubernetes (staging/production)
deploy_with_kubernetes() {
    log "Deploying with Kubernetes for ${ENVIRONMENT}..."
    
    # Apply Kubernetes manifests
    kubectl apply -f k8s/namespace.yml
    kubectl apply -f k8s/configmap.yml -n ${NAMESPACE}
    kubectl apply -f k8s/deployment.yml -n ${NAMESPACE}
    kubectl apply -f k8s/service.yml -n ${NAMESPACE}
    kubectl apply -f k8s/ingress.yml -n ${NAMESPACE}
    
    # Wait for deployment to be ready
    kubectl rollout status deployment/osint-suite -n ${NAMESPACE} --timeout=300s
    
    success "Kubernetes deployment completed"
}

# Health checks
run_health_checks() {
    log "Running health checks..."
    
    # Wait for services to be ready
    sleep 30
    
    # Check application health
    if [[ ${ENVIRONMENT} == "development" ]]; then
        HEALTH_URL="http://localhost:8080/health"
    else
        HEALTH_URL="https://osint-${ENVIRONMENT}.example.com/health"
    fi
    
    # Retry health check
    for i in {1..10}; do
        if curl -f -s ${HEALTH_URL} > /dev/null; then
            success "Health check passed"
            return 0
        fi
        log "Health check attempt ${i}/10 failed, retrying in 10 seconds..."
        sleep 10
    done
    
    error "Health checks failed after 10 attempts"
}

# Run smoke tests
run_smoke_tests() {
    log "Running smoke tests..."
    
    # Run basic functionality tests
    if [[ ${ENVIRONMENT} == "development" ]]; then
        docker-compose exec osint-suite python final_test.py
    else
        kubectl run smoke-test -n ${NAMESPACE} \
            --image=${REGISTRY}:${VERSION} \
            --rm -i --restart=Never \
            -- python final_test.py
    fi
    
    success "Smoke tests completed"
}

# Security validation
run_security_checks() {
    log "Running security validation..."
    
    # Check for exposed secrets
    if kubectl get secrets -n ${NAMESPACE} -o yaml | grep -E "(password|key|token)" | grep -v "type:"; then
        warning "Potential exposed secrets detected - please review"
    fi
    
    # Vulnerability scan
    if command -v trivy &> /dev/null; then
        trivy image ${REGISTRY}:${VERSION}
    else
        warning "Trivy not available - skipping vulnerability scan"
    fi
    
    success "Security checks completed"
}

# Monitoring setup
setup_monitoring() {
    log "Setting up monitoring for ${ENVIRONMENT}..."
    
    # Deploy monitoring stack
    if [[ ${ENVIRONMENT} != "development" ]]; then
        kubectl apply -f k8s/monitoring/ -n ${NAMESPACE}
        
        # Wait for monitoring components
        kubectl rollout status deployment/prometheus -n ${NAMESPACE} --timeout=300s
        kubectl rollout status deployment/grafana -n ${NAMESPACE} --timeout=300s
    fi
    
    success "Monitoring setup completed"
}

# Cleanup old deployments
cleanup() {
    log "Cleaning up old deployments..."
    
    if [[ ${ENVIRONMENT} != "development" ]]; then
        # Keep last 3 deployments
        kubectl get deployments -n ${NAMESPACE} -o jsonpath='{.items[*].metadata.name}' | \
        xargs -n1 | sort -r | tail -n +4 | \
        xargs -r kubectl delete deployment -n ${NAMESPACE}
    fi
    
    success "Cleanup completed"
}

# Rollback function
rollback() {
    log "Rolling back deployment..."
    
    if [[ ${ENVIRONMENT} == "development" ]]; then
        docker-compose down
        git checkout HEAD~1
        docker-compose up -d --build
    else
        kubectl rollout undo deployment/osint-suite -n ${NAMESPACE}
        kubectl rollout status deployment/osint-suite -n ${NAMESPACE}
    fi
    
    success "Rollback completed"
}

# Main deployment function
main() {
    log "Starting OSINT Suite deployment to ${ENVIRONMENT} with version ${VERSION}"
    
    # Trap errors and rollback
    trap 'error "Deployment failed. Starting rollback..."; rollback' ERR
    
    validate_environment
    check_prerequisites
    generate_secrets
    deploy_infrastructure
    run_health_checks
    run_smoke_tests
    run_security_checks
    setup_monitoring
    cleanup
    
    success "🚀 OSINT Suite deployment to ${ENVIRONMENT} completed successfully!"
    
    # Display access information
    log "Access Information:"
    if [[ ${ENVIRONMENT} == "development" ]]; then
        echo "  Application: http://localhost:8080"
        echo "  Grafana: http://localhost:3000 (admin/admin123)"
        echo "  Prometheus: http://localhost:9090"
    else
        echo "  Application: https://osint-${ENVIRONMENT}.example.com"
        echo "  Grafana: https://grafana-${ENVIRONMENT}.example.com"
        echo "  Prometheus: https://prometheus-${ENVIRONMENT}.example.com"
    fi
}

# Help function
show_help() {
    cat << EOF
OSINT Suite CI/CD Deployment Script

Usage: $0 [ENVIRONMENT] [VERSION]

Arguments:
  ENVIRONMENT    Target environment (development, staging, production)
  VERSION        Container image version (default: latest)

Examples:
  $0 development
  $0 staging v1.2.3
  $0 production latest

Options:
  --rollback     Rollback to previous deployment
  --help         Show this help message

EOF
}

# Handle arguments
case "${1:-}" in
    --help|-h)
        show_help
        exit 0
        ;;
    --rollback)
        rollback
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac