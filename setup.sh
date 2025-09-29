#!/usr/bin/env bash
# Passive OSINT Suite - Quick Setup Script
# Automated installation and configuration for new users

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if [[ -f /etc/debian_version ]]; then
            DISTRO="debian"
        elif [[ -f /etc/redhat-release ]]; then
            DISTRO="redhat"
        else
            DISTRO="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
    else
        OS="unknown"
        DISTRO="unknown"
    fi
    
    log "Detected OS: $OS ($DISTRO)"
}

# Check dependencies
check_dependencies() {
    log "Checking system dependencies..."
    
    # Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is required but not installed"
        exit 1
    fi
    
    python_version=$(python3 --version | cut -d' ' -f2)
    log "Found Python $python_version"
    
    # Git
    if ! command -v git &> /dev/null; then
        error "Git is required but not installed"
        exit 1
    fi
    
    # Optional: Docker
    if command -v docker &> /dev/null; then
        log "Docker found - containerized deployment available"
    else
        warn "Docker not found - some features may be limited"
    fi
    
    # Optional: Node.js for web interface
    if command -v node &> /dev/null; then
        log "Node.js found - web interface available"
    else
        warn "Node.js not found - web interface will be limited"
    fi
}

# Install system dependencies
install_system_deps() {
    log "Installing system dependencies..."
    
    if [[ "$DISTRO" == "debian" ]]; then
        if command -v apt-get &> /dev/null; then
            log "Installing via apt-get..."
            sudo apt-get update
            sudo apt-get install -y python3-pip python3-venv build-essential libssl-dev libffi-dev tor
        fi
    elif [[ "$DISTRO" == "redhat" ]]; then
        if command -v yum &> /dev/null; then
            log "Installing via yum..."
            sudo yum install -y python3-pip python3-venv gcc openssl-devel libffi-devel tor
        elif command -v dnf &> /dev/null; then
            log "Installing via dnf..."
            sudo dnf install -y python3-pip python3-venv gcc openssl-devel libffi-devel tor
        fi
    elif [[ "$DISTRO" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            log "Installing via Homebrew..."
            brew install python3 tor
        else
            warn "Homebrew not found - please install dependencies manually"
        fi
    else
        warn "Unknown distribution - please install dependencies manually"
    fi
}

# Setup Python virtual environment
setup_python_env() {
    log "Setting up Python virtual environment..."
    
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        log "Created virtual environment"
    else
        log "Virtual environment already exists"
    fi
    
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        log "Installing Python dependencies..."
        pip install -r requirements.txt
    else
        error "requirements.txt not found"
        exit 1
    fi
    
    log "Python environment setup complete"
}

# Setup configuration
setup_config() {
    log "Setting up configuration..."
    
    # Create .env file from template
    if [[ ! -f ".env" ]]; then
        if [[ -f ".env.example" ]]; then
            cp .env.example .env
            log "Created .env file from template"
            warn "Please edit .env file with your actual API keys and configuration"
        else
            error ".env.example template not found"
            exit 1
        fi
    else
        log ".env file already exists"
    fi
    
    # Set proper permissions
    chmod 600 .env
    if [[ -f "config/config.ini" ]]; then
        chmod 600 config/config.ini
    fi
    
    # Create required directories
    mkdir -p logs output investigations templates security
    mkdir -p output/encrypted output/audit
    
    log "Configuration setup complete"
}

# Setup web interface
setup_web_interface() {
    if [[ -d "web" ]] && [[ -f "web/package.json" ]]; then
        log "Setting up web interface..."
        
        if command -v npm &> /dev/null; then
            cd web
            npm install
            cd ..
            log "Web interface dependencies installed"
        else
            warn "npm not found - web interface setup skipped"
        fi
    else
        log "No web interface found - skipping"
    fi
}

# Generate secure keys
generate_keys() {
    log "Generating secure keys..."
    
    # Generate random keys for .env if they don't exist
    if grep -q "your_very_long_random_secret_key_here" .env 2>/dev/null; then
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
        
        sed -i "s/your_very_long_random_secret_key_here_minimum_32_characters/$SECRET_KEY/" .env
        sed -i "s/your_jwt_secret_key_here_minimum_32_characters/$JWT_SECRET/" .env
        sed -i "s/your_32_character_encryption_key/$ENCRYPTION_KEY/" .env
        
        log "Generated secure keys in .env file"
    else
        log "Keys already configured in .env file"
    fi
}

# Run health check
run_health_check() {
    log "Running system health check..."
    
    source venv/bin/activate
    python health_check.py || warn "Health check completed with warnings"
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}✅ Passive OSINT Suite setup complete!${NC}"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Edit .env file with your API keys: nano .env"
    echo "2. Activate virtual environment: source venv/bin/activate"
    echo "3. Run the suite: python main.py"
    echo "4. Or start the API server: python api/api_server.py"
    echo "5. Or use Docker: docker-compose up -d"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "• README.md - General usage and features"
    echo "• DEPLOYMENT.md - Production deployment guide"
    echo "• STARTUP_GUIDE.md - Quick start tutorial"
    echo
    echo -e "${YELLOW}Security reminders:${NC}"
    echo "• Never commit .env or config.ini files to version control"
    echo "• Use strong, unique passwords for all services"
    echo "• Regularly rotate API keys and secrets"
    echo "• Run 'python scripts/security_audit.py' for security checks"
    echo
}

# Main installation function
main() {
    echo -e "${BLUE}🚀 Passive OSINT Suite - Quick Setup${NC}"
    echo "================================================"
    
    check_root
    detect_os
    check_dependencies
    
    # Ask for confirmation
    echo
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Installation cancelled"
        exit 0
    fi
    
    # Run installation steps
    install_system_deps
    setup_python_env
    setup_config
    setup_web_interface
    generate_keys
    run_health_check
    print_completion
}

# Handle command line arguments
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "Passive OSINT Suite - Quick Setup Script"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --skip-deps    Skip system dependency installation"
    echo "  --skip-web     Skip web interface setup"
    echo "  --skip-health  Skip health check"
    echo
    echo "This script will:"
    echo "1. Install system dependencies (Python, Tor, etc.)"
    echo "2. Create Python virtual environment"
    echo "3. Install Python packages"
    echo "4. Setup configuration files"
    echo "5. Generate secure keys"
    echo "6. Run health check"
    echo
    exit 0
fi

# Skip flags
SKIP_DEPS=false
SKIP_WEB=false
SKIP_HEALTH=false

for arg in "$@"; do
    case $arg in
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --skip-web)
            SKIP_WEB=true
            shift
            ;;
        --skip-health)
            SKIP_HEALTH=true
            shift
            ;;
    esac
done

# Run main installation
main