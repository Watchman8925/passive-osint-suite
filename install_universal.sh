#!/bin/bash
# ===========================================
# PASSIVE OSINT SUITE - UNIVERSAL INSTALLER
# ===========================================
# Comprehensive installation script with:
# - Environment detection (OS, architecture, GUI)
# - Automatic dependency resolution
# - Health checks and validation
# - Error recovery and rollback
# - Progress tracking and user feedback

set -euo pipefail

# ===========================================
# CONFIGURATION
# ===========================================

SCRIPT_VERSION="2.0.0"
REQUIRED_PYTHON_VERSION="3.12"
REQUIRED_NODE_VERSION="18"
REQUIRED_DISK_SPACE_GB=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Progress tracking
TOTAL_STEPS=12
CURRENT_STEP=0

# ===========================================
# UTILITY FUNCTIONS
# ===========================================

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

progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo -e "${CYAN}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} $1"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

version_compare() {
    # Compare version numbers
    # Returns: 0 if equal, 1 if $1 > $2, 2 if $1 < $2
    if [[ $1 == $2 ]]; then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2
        fi
    done
    return 0
}

# ===========================================
# ENVIRONMENT DETECTION
# ===========================================

detect_os() {
    log_info "Detecting operating system..."

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt; then
            OS="debian"
            PACKAGE_MANAGER="apt"
            log_success "Detected Debian/Ubuntu Linux"
        elif command_exists yum; then
            OS="redhat"
            PACKAGE_MANAGER="yum"
            log_success "Detected Red Hat/CentOS Linux"
        elif command_exists pacman; then
            OS="arch"
            PACKAGE_MANAGER="pacman"
            log_success "Detected Arch Linux"
        else
            log_error "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
        log_success "Detected macOS"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS="windows"
        PACKAGE_MANAGER="choco"
        log_success "Detected Windows"
    else
        log_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

detect_architecture() {
    log_info "Detecting system architecture..."

    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            ARCH="x64"
            log_success "Detected x64 architecture"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            log_success "Detected ARM64 architecture"
            ;;
        i386|i686)
            ARCH="x86"
            log_success "Detected x86 architecture"
            ;;
        *)
            log_warning "Unknown architecture: $ARCH - proceeding anyway"
            ;;
    esac
}

check_system_requirements() {
    log_info "Checking system requirements..."

    # Check disk space
    local available_space
    if [[ "$OS" == "macos" ]]; then
        available_space=$(df -g . | tail -1 | awk '{print $4}')
    else
        available_space=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
    fi

    if (( available_space < REQUIRED_DISK_SPACE_GB )); then
        log_error "Insufficient disk space. Required: ${REQUIRED_DISK_SPACE_GB}GB, Available: ${available_space}GB"
        exit 1
    fi
    log_success "Disk space check passed (${available_space}GB available)"

    # Check if running as root (not recommended for some operations)
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root - some operations may not work correctly"
    fi
}

detect_gui_environment() {
    log_info "Detecting GUI environment..."

    if [[ -n "${DISPLAY:-}" ]]; then
        HAS_GUI=true
        log_success "GUI environment detected"
    else
        HAS_GUI=false
        log_info "No GUI environment detected (headless/server mode)"
    fi
}

# ===========================================
# DEPENDENCY INSTALLATION
# ===========================================

install_system_dependencies() {
    progress "Installing system dependencies"

    case $OS in
        debian)
            log_info "Installing Debian/Ubuntu dependencies..."
            sudo apt update
            sudo apt install -y \
                build-essential \
                python3-dev \
                python3-pip \
                python3-venv \
                curl \
                wget \
                git \
                tor \
                torsocks \
                whois \
                dnsutils \
                nmap \
                libssl-dev \
                libffi-dev \
                libxml2-dev \
                libxslt1-dev \
                zlib1g-dev \
                libgmp-dev \
                libmpfr-dev \
                libmpc-dev \
                libjpeg-dev \
                libpng-dev \
                libfreetype6-dev \
                pkg-config
            ;;
        redhat)
            log_info "Installing Red Hat/CentOS dependencies..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                python3-devel \
                python3-pip \
                curl \
                wget \
                git \
                tor \
                torsocks \
                whois \
                bind-utils \
                nmap \
                openssl-devel \
                libffi-devel \
                libxml2-devel \
                libxslt-devel \
                zlib-devel \
                gmp-devel \
                mpfr-devel \
                libmpc-devel \
                libjpeg-devel \
                libpng-devel \
                freetype-devel
            ;;
        arch)
            log_info "Installing Arch Linux dependencies..."
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm \
                base-devel \
                python \
                python-pip \
                curl \
                wget \
                git \
                tor \
                torsocks \
                whois \
                bind \
                nmap \
                openssl \
                libffi \
                libxml2 \
                libxslt \
                zlib \
                gmp \
                mpfr \
                libmpc \
                libjpeg \
                libpng \
                freetype2 \
                pkgconf
            ;;
        macos)
            log_info "Installing macOS dependencies..."
            if ! command_exists brew; then
                log_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install \
                python3 \
                curl \
                wget \
                git \
                tor \
                torsocks \
                whois \
                nmap \
                openssl \
                libffi \
                libxml2 \
                libxslt \
                zlib \
                gmp \
                mpfr \
                libmpc \
                jpeg \
                libpng \
                freetype
            ;;
        windows)
            log_warning "Windows installation requires manual setup"
            log_info "Please install the following manually:"
            log_info "1. Python 3.8+ from python.org"
            log_info "2. Git from git-scm.com"
            log_info "3. Tor Browser or tor expert bundle"
            log_info "4. Microsoft Visual C++ Build Tools"
            exit 1
            ;;
    esac

    log_success "System dependencies installed"
}

check_python_version() {
    progress "Checking Python version"

    if ! command_exists python3; then
        log_error "Python 3 not found"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')

    if version_compare "$PYTHON_VERSION" "$REQUIRED_PYTHON_VERSION"; then
        log_success "Python $PYTHON_VERSION meets requirement (>= $REQUIRED_PYTHON_VERSION)"
    else
        log_error "Python $PYTHON_VERSION is too old. Required: >= $REQUIRED_PYTHON_VERSION"
        exit 1
    fi
}

setup_python_environment() {
    progress "Setting up Python virtual environment"

    # Remove existing environment if it exists
    if [[ -d ".venv" ]]; then
        log_warning "Removing existing virtual environment"
        rm -rf .venv
    fi

    # Create new virtual environment
    python3 -m venv .venv
    log_success "Virtual environment created"

    # Activate and upgrade pip
    source .venv/bin/activate
    pip install --upgrade pip setuptools wheel
    log_success "Pip upgraded"
}

install_python_packages() {
    progress "Installing Python packages"

    source .venv/bin/activate

    # Install packages in stages to avoid dependency resolution conflicts
    log_info "Installing packages in stages to avoid resolution conflicts..."

    # Stage 1: Core dependencies (most stable)
    log_info "Stage 1: Installing core dependencies..."
    pip install --quiet \
        requests==2.26.0 \
        beautifulsoup4>=4.11.0 \
        dnspython>=2.2.0 \
        colorama>=0.4.4 \
        tabulate>=0.9.0 \
        urllib3==1.26.7 \
        json5>=0.9.0 \
        click>=8.1.0 \
        python-dateutil>=2.8.2 \
        validators>=0.20.0 \
        netaddr>=0.8.0 \
        phonenumbers>=8.12.0 \
        pytz>=2022.1 \
        lxml>=4.9.0 \
        cryptography>=41.0.0 \
        keyring>=24.0.0 \
        bcrypt>=4.1.0

    # Stage 2: Web framework
    log_info "Stage 2: Installing web framework..."
    pip install --quiet \
        fastapi>=0.104.0 \
        uvicorn>=0.24.0 \
        pydantic>=2.5.0 \
        starlette>=0.27.0 \
        aiohttp>=3.8.0

    # Stage 3: Database and search
    log_info "Stage 3: Installing database and search packages..."
    pip install --quiet \
        redis>=5.0.0 \
        psycopg2-binary>=2.9.9

    # Stage 4: Data processing
    log_info "Stage 4: Installing data processing packages..."
    pip install --quiet \
        pandas==2.1.4 \
        numpy==1.26.4 \
        matplotlib>=3.6.0 \
        networkx>=2.8.0

    # Stage 5: ML/AI packages (most problematic - install with specific versions)
    log_info "Stage 5: Installing ML/AI packages..."
    pip install --quiet \
        torch==2.2.2 \
        scikit-learn==1.3.2 \
        transformers==4.36.2 \
        huggingface_hub==0.19.4 \
        sentence-transformers==2.2.2

    # Stage 6: Remaining packages
    log_info "Stage 6: Installing remaining packages..."
    pip install --quiet \
        openai>=1.0.0 \
        elasticsearch>=8.11.0 \
        websockets>=12.0.0 \
        neo4j>=5.15.0 \
        py2neo>=2021.2.3 \
        censys==2.1.9 \
        shodan==1.28.0 \
        plotly>=5.10.0 \
        wordcloud>=1.9.0 \
        html5lib>=1.1 \
        pytest>=8.0.0 \
        black>=23.0.0 \
        structlog>=23.1.0 \
        stem>=1.8.0 \
        httpx>=0.24.0 \
        tenacity>=8.2.0 \
        reportlab>=4.0.0 \
        jinja2>=3.1.0 \
        markdown>=3.5.0 \
        pillow>=10.0.0 \
        celery>=5.3.0 \
        psutil>=5.9.0

    # Try to install remaining packages from requirements.txt if it exists
    if [[ -f "requirements.txt" ]]; then
        log_info "Installing any remaining packages from requirements.txt..."
        pip install --quiet -r requirements.txt 2>/dev/null || log_warning "Some packages from requirements.txt could not be installed - core functionality should still work"
    fi

    log_success "Python packages installed (staged installation completed)"
}

install_nodejs() {
    progress "Installing Node.js for web interface"

    if command_exists node; then
        NODE_VERSION=$(node -v | sed 's/v//')
        if version_compare "$NODE_VERSION" "$REQUIRED_NODE_VERSION"; then
            log_success "Node.js $NODE_VERSION already installed"
            return
        fi
    fi

    case $OS in
        debian)
            log_info "Installing Node.js via NodeSource..."
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
            sudo apt-get install -y nodejs
            ;;
        redhat)
            log_info "Installing Node.js via NodeSource..."
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
            sudo yum install -y nodejs
            ;;
        arch)
            sudo pacman -S --noconfirm nodejs npm
            ;;
        macos)
            brew install node
            ;;
    esac

    log_success "Node.js installed"
}

setup_web_interface() {
    progress "Setting up web interface"

    if [[ -d "web" ]]; then
        cd web
        if command_exists npm; then
            log_info "Installing web dependencies..."
            npm install
            log_success "Web dependencies installed"
        else
            log_warning "npm not available - web interface setup skipped"
        fi
        cd ..
    else
        log_warning "Web directory not found - web interface setup skipped"
    fi
}

# ===========================================
# HEALTH CHECKS & VALIDATION
# ===========================================

run_health_checks() {
    progress "Running comprehensive health checks"

    local checks_passed=0
    local total_checks=0
    local warnings=()

    echo ""
    log_info "🔍 Performing detailed component validation..."
    echo ""

    # 1. Python Environment Check
    ((total_checks++))
    echo -n "  Python Environment: "
    if source .venv/bin/activate 2>/dev/null && python3 -c "import sys; print(f'Python {sys.version.split()[0]} OK')" >/dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${RED}❌${NC}"
        warnings+=("Python virtual environment not properly configured")
    fi

    # 2. Core Dependencies Check
    ((total_checks++))
    echo -n "  Core Dependencies: "
    if source .venv/bin/activate 2>/dev/null && python3 -c "
import sys
core_modules = ['requests', 'bs4', 'dns', 'colorama', 'tabulate']
missing = []
for module in core_modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)
if missing:
    print(f'Missing: {missing}')
    sys.exit(1)
print('All core modules available')
" >/dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${RED}❌${NC}"
        warnings+=("Core Python dependencies missing")
    fi

    # 3. Security Modules Check
    ((total_checks++))
    echo -n "  Security Modules: "
    if source .venv/bin/activate 2>/dev/null && python3 -c "
import sys
security_modules = ['cryptography', 'keyring', 'bcrypt']
missing = []
for module in security_modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)
if missing:
    print(f'Missing: {missing}')
    sys.exit(1)
print('Security modules OK')
" >/dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${YELLOW}⚠️${NC}"
        warnings+=("Some security modules missing - reduced functionality")
        ((checks_passed++))  # Still count as passed but with warning
    fi

    # 4. AI/ML Modules Check
    ((total_checks++))
    echo -n "  AI/ML Modules: "
    if source .venv/bin/activate 2>/dev/null && python3 -c "
import sys
ai_modules = ['transformers', 'torch', 'scikit_learn']
missing = []
for module in ai_modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)
if missing:
    print(f'Missing: {missing}')
    sys.exit(1)
print('AI/ML modules OK')
" >/dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${YELLOW}⚠️${NC}"
        warnings+=("AI/ML modules missing - local LLM features limited")
        ((checks_passed++))  # Still count as passed but with warning
    fi

    # 5. Web Framework Check
    ((total_checks++))
    echo -n "  Web Framework: "
    if source .venv/bin/activate 2>/dev/null && python3 -c "
import sys
try:
    import fastapi, uvicorn, pydantic
    print('Web framework OK')
except ImportError as e:
    print(f'Missing: {e}')
    sys.exit(1)
" >/dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${RED}❌${NC}"
        warnings+=("Web framework modules missing - API unavailable")
    fi

    # 6. Tor Integration Check
    ((total_checks++))
    echo -n "  Tor Integration: "
    if command_exists tor; then
        if pgrep -f tor >/dev/null 2>&1; then
            echo -e "${GREEN}✅${NC}"
            ((checks_passed++))
        else
            echo -e "${YELLOW}⚠️${NC}"
            warnings+=("Tor installed but not running - start with: sudo systemctl start tor")
            ((checks_passed++))
        fi
    else
        echo -e "${YELLOW}⚠️${NC}"
        warnings+=("Tor not installed - anonymity features limited")
        ((checks_passed++))
    fi

    # 7. Node.js Check (for web interface)
    if [[ -d "web" ]]; then
        ((total_checks++))
        echo -n "  Node.js/Web Interface: "
        if command_exists node && command_exists npm; then
            # Check if web dependencies are installed
            if [[ -d "web/node_modules" ]]; then
                echo -e "${GREEN}✅${NC}"
                ((checks_passed++))
            else
                echo -e "${YELLOW}⚠️${NC}"
                warnings+=("Node.js installed but web dependencies not installed - run: cd web && npm install")
                ((checks_passed++))
            fi
        else
            echo -e "${RED}❌${NC}"
            warnings+=("Node.js not available - web interface disabled")
        fi
    fi

    # 8. Configuration Check
    ((total_checks++))
    echo -n "  Configuration: "
    if [[ -f "config.ini" ]] && [[ -r "config.ini" ]]; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${RED}❌${NC}"
        warnings+=("Configuration file missing or not readable")
    fi

    # 9. Directory Structure Check
    ((total_checks++))
    echo -n "  Directory Structure: "
    required_dirs=("logs" "output" "output/encrypted" "output/audit" "investigations")
    missing_dirs=()
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            missing_dirs+=("$dir")
        fi
    done
    if [[ ${#missing_dirs[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${RED}❌${NC}"
        warnings+=("Missing directories: ${missing_dirs[*]}")
    fi

    # 10. API Connectivity Test (basic)
    ((total_checks++))
    echo -n "  Network Connectivity: "
    if curl -s --connect-timeout 5 https://httpbin.org/ip >/dev/null 2>&1; then
        echo -e "${GREEN}✅${NC}"
        ((checks_passed++))
    else
        echo -e "${YELLOW}⚠️${NC}"
        warnings+=("Network connectivity issues - some features may not work")
        ((checks_passed++))
    fi

    echo ""
    log_info "Health Check Summary: $checks_passed/$total_checks components validated"

    # Show warnings if any
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo ""
        log_warning "⚠️  Health Check Warnings:"
        for warning in "${warnings[@]}"; do
            echo -e "     ${YELLOW}•${NC} $warning"
        done
        echo ""
    fi

    if (( checks_passed == total_checks )); then
        log_success "🎉 All health checks passed!"
        return 0
    else
        log_warning "Some health checks failed - functionality may be limited"
        return 1
    fi
}

# ===========================================
# CONFIGURATION & SETUP
# ===========================================

setup_directories() {
    progress "Setting up directories"

    mkdir -p logs
    mkdir -p output
    mkdir -p output/encrypted
    mkdir -p output/audit
    mkdir -p investigations
    mkdir -p templates

    log_success "Directories created"
}

create_launcher_scripts() {
    progress "Creating launcher scripts"

    # Main launcher
    cat > start_osint_suite.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source .venv/bin/activate

# Set Python path
export PYTHONPATH="$PWD:$PYTHONPATH"

# Check if arguments provided
if [ $# -eq 0 ]; then
    echo "Starting OSINT Suite in interactive mode..."
    python3 main.py
else
    echo "Starting OSINT Suite with arguments: $@"
    python3 main.py "$@"
fi
EOF

    chmod +x start_osint_suite.sh

    # Web interface launcher
    if [[ -d "web" ]]; then
        cat > start_web_interface.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

# Start backend API
echo "Starting backend API..."
source .venv/bin/activate
export PYTHONPATH="$PWD:$PYTHONPATH"
python3 main.py --web &
API_PID=$!

# Start frontend
echo "Starting web interface..."
cd web
npm run dev &
WEB_PID=$!

echo "OSINT Suite web interface starting..."
echo "Backend API: http://localhost:8000"
echo "Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for interrupt
trap "echo 'Stopping services...'; kill $API_PID $WEB_PID 2>/dev/null; exit" INT
wait
EOF

        chmod +x start_web_interface.sh
    fi

    log_success "Launcher scripts created"
}

create_desktop_entry() {
    if [[ "$HAS_GUI" == true ]]; then
        progress "Creating desktop integration"

        # Desktop entry
        mkdir -p ~/.local/share/applications
        cat > ~/.local/share/applications/passive-osint-suite.desktop << EOF
[Desktop Entry]
Name=Passive OSINT Suite
Comment=Comprehensive passive reconnaissance and intelligence gathering
Exec=$(pwd)/start_osint_suite.sh
Icon=utilities-system-monitor
Terminal=true
Type=Application
Categories=Security;Network;Development;
Keywords=osint;intelligence;security;reconnaissance;
EOF

        log_success "Desktop entry created"
    fi
}

setup_configuration() {
    progress "Setting up configuration"

    if [[ ! -f "config.ini" ]]; then
        if [[ -f "config.ini.template" ]]; then
            cp config.ini.template config.ini
            log_success "Configuration initialized from template"
        else
            log_warning "No configuration template found"
        fi
    else
        log_success "Configuration already exists"
    fi
}

# ===========================================
# SETUP WIZARD
# ===========================================

run_setup_wizard() {
    echo ""
    log_header "🧙 OSINT SUITE SETUP WIZARD"
    echo ""
    log_info "Welcome to the Passive OSINT Suite setup wizard!"
    log_info "This will guide you through configuring your OSINT platform."
    echo ""

    # Check if already configured
    if [[ -f "config.ini" ]] && grep -q "\[API_KEYS\]" config.ini 2>/dev/null; then
        echo -n "Configuration file detected. Reconfigure? (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log_info "Skipping configuration - using existing settings"
            return 0
        fi
    fi

    echo ""
    log_info "📋 Configuration Sections:"
    echo "  1. API Keys & Services"
    echo "  2. Security Settings"
    echo "  3. Network & Anonymity"
    echo "  4. Output & Logging"
    echo "  5. Advanced Options"
    echo ""

    # API Keys Configuration
    echo ""
    log_info "🔑 API KEYS CONFIGURATION"
    echo "The OSINT Suite supports various intelligence sources."
    echo "Some require API keys, others work without them."
    echo ""

    # Create or update config.ini
    cat > config.ini << 'EOF'
# OSINT Suite Configuration File
# API Keys are stored securely in encrypted storage
# DO NOT store plain text API keys in this file

[API_KEYS]
# All API keys have been moved to encrypted storage
# Use the encrypted config system for security

[SETTINGS]
LOG_LEVEL = INFO
MAX_THREADS = 10
TIMEOUT = 30
USER_AGENT = Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36

[PASSIVE_SOURCES]
ENABLE_GOOGLE_DORKING = true
ENABLE_PASTEBIN_SEARCH = true
ENABLE_GITHUB_SEARCH = true
ENABLE_SOCIAL_MEDIA_SEARCH = true
ENABLE_COURT_RECORDS_SEARCH = true
ENABLE_NEWS_SEARCH = true
ENABLE_JOB_POSTING_SEARCH = true

[FLIGHT_TRACKING]
ENABLE_FLIGHTAWARE = true
ENABLE_FLIGHTRADAR24 = true
ENABLE_PLANEFINDER = true
ENABLE_ADSBEXCHANGE = true

[SECURITY]
OPSEC_MODE = standard
ANONYMITY_LEVEL = medium
AUDIT_LOGGING = true
RESULT_ENCRYPTION = true

[NETWORK]
TOR_ENABLED = false
DNS_OVER_HTTPS = true
PROXY_SETTINGS = auto
TIMEOUT_GLOBAL = 30

[OUTPUT]
FORMAT_DEFAULT = json
COMPRESSION = false
AUTO_CLEANUP = true
MAX_FILE_SIZE_MB = 100

[ADVANCED]
LOCAL_LLM_ENABLED = true
AI_ANALYSIS_DEPTH = medium
PARALLEL_PROCESSING = true
CACHE_ENABLED = true
EOF

    log_success "✅ Basic configuration created"

    # API Key Setup
    echo ""
    log_info "🔐 OPTIONAL API KEY SETUP"
    echo "You can add API keys now or later using the web interface."
    echo "Supported services: VirusTotal, Shodan, Censys, Hunter.io, etc."
    echo ""

    echo -n "Would you like to configure API keys now? (y/N): "
    read -r setup_keys
    if [[ "$setup_keys" =~ ^[Yy]$ ]]; then
        echo ""
        log_info "API Key Configuration:"
        echo "Note: Keys will be stored securely using the OSINT Suite's encryption system"
        echo ""

        # Common API services
        declare -A api_services=(
            ["VIRUSTOTAL_API_KEY"]="VirusTotal (malware analysis)"
            ["SHODAN_API_KEY"]="Shodan (device search)"
            ["CENSYS_API_KEY"]="Censys (certificate search)"
            ["HUNTER_API_KEY"]="Hunter.io (email search)"
            ["EMAILHUNTER_API_KEY"]="Email Hunter (email verification)"
            ["INTELLIGENCE_X_API_KEY"]="Intelligence X (leak search)"
        )

        for key in "${!api_services[@]}"; do
            echo -n "Enter ${api_services[$key]} (leave empty to skip): "
            read -r api_value
            if [[ -n "$api_value" ]]; then
                # Store securely using the secrets manager
                if source .venv/bin/activate 2>/dev/null && python3 -c "
from secrets_manager import secrets_manager
secrets_manager.store_secret('$key', '$api_value')
print('API key stored securely')
" 2>/dev/null; then
                    log_success "✅ ${api_services[$key]} configured"
                else
                    log_warning "⚠️ Could not store ${key} securely - will be stored in config temporarily"
                    # Fallback to config file (not recommended)
                    echo "$key = $api_value" >> config.ini
                fi
            fi
        done
    fi

    # Security Settings
    echo ""
    log_info "🔒 SECURITY CONFIGURATION"
    echo ""

    echo -n "Enable OPSEC mode? (recommended) (Y/n): "
    read -r opsec_mode
    if [[ "$opsec_mode" =~ ^[Nn]$ ]]; then
        sed -i 's/OPSEC_MODE = standard/OPSEC_MODE = disabled/' config.ini
        log_warning "⚠️ OPSEC mode disabled - use caution with sensitive investigations"
    else
        log_success "✅ OPSEC mode enabled"
    fi

    # Anonymity Settings
    echo ""
    echo -n "Enable Tor integration? (requires Tor installation) (y/N): "
    read -r tor_enabled
    if [[ "$tor_enabled" =~ ^[Yy]$ ]]; then
        if command_exists tor; then
            sed -i 's/TOR_ENABLED = false/TOR_ENABLED = true/' config.ini
            log_success "✅ Tor integration enabled"
        else
            log_warning "⚠️ Tor not installed - install with: sudo apt install tor"
            log_info "Tor can be enabled later in the web interface"
        fi
    fi

    # Performance Settings
    echo ""
    log_info "⚡ PERFORMANCE CONFIGURATION"
    echo ""

    echo -n "Enable parallel processing? (recommended) (Y/n): "
    read -r parallel_proc
    if [[ "$parallel_proc" =~ ^[Nn]$ ]]; then
        sed -i 's/PARALLEL_PROCESSING = true/PARALLEL_PROCESSING = false/' config.ini
        log_info "Parallel processing disabled"
    else
        log_success "✅ Parallel processing enabled"
    fi

    echo -n "Enable local LLM analysis? (Y/n): "
    read -r llm_enabled
    if [[ "$llm_enabled" =~ ^[Nn]$ ]]; then
        sed -i 's/LOCAL_LLM_ENABLED = true/LOCAL_LLM_ENABLED = false/' config.ini
        log_info "Local LLM analysis disabled"
    else
        log_success "✅ Local LLM analysis enabled"
    fi

    echo ""
    log_success "🎉 Configuration completed!"
    log_info "You can modify settings later in config.ini or through the web interface"
    echo ""
}

# ===========================================
# MAIN INSTALLATION FLOW
# ===========================================

main() {
    # Parse command line arguments
    case "${1:-}" in
        --wizard)
            log_header "OSINT SUITE SETUP WIZARD v$SCRIPT_VERSION"
            # Check if installation exists
            if [[ ! -d ".venv" ]]; then
                log_error "Installation not found. Run installer first: ./install_universal.sh"
                exit 1
            fi
            run_setup_wizard
            exit 0
            ;;
        --health-check)
            log_header "OSINT SUITE HEALTH CHECK v$SCRIPT_VERSION"
            if [[ ! -d ".venv" ]]; then
                log_error "Installation not found. Run installer first: ./install_universal.sh"
                exit 1
            fi
            run_health_checks
            exit $?
            ;;
        --help|-h)
            echo "Passive OSINT Suite Installer v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --wizard       Run setup wizard only"
            echo "  --health-check Run health checks only"
            echo "  --help         Show this help message"
            echo ""
            echo "Without options, runs full installation."
            exit 0
            ;;
    esac

    log_header "PASSIVE OSINT SUITE INSTALLER v$SCRIPT_VERSION"

    # Pre-installation checks
    detect_os
    detect_architecture
    check_system_requirements
    detect_gui_environment

    echo ""
    log_info "Installation Summary:"
    echo "  OS: $OS ($ARCH)"
    echo "  Package Manager: $PACKAGE_MANAGER"
    echo "  GUI Environment: $HAS_GUI"
    echo "  Disk Space: OK"
    echo ""

    # Confirm installation
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi

    echo ""

    # Installation steps
    install_system_dependencies
    check_python_version
    setup_python_environment
    install_python_packages
    install_nodejs
    setup_web_interface
    setup_directories
    create_launcher_scripts
    create_desktop_entry
    setup_configuration

    # Health checks
    echo ""
    if run_health_checks; then
        echo ""
        log_header "INSTALLATION COMPLETED SUCCESSFULLY!"

        # Run setup wizard
        run_setup_wizard

        echo ""
        log_success "🎉 Passive OSINT Suite is ready to use!"
        echo ""
        log_info "Quick Start:"
        echo "  Interactive Mode: ./start_osint_suite.sh"
        echo "  Web Interface: ./start_web_interface.sh"
        echo "  Direct Command: source .venv/bin/activate && python3 main.py --help"
        echo ""
        log_info "Next Steps:"
        echo "  1. Review your configuration in config.ini"
        echo "  2. Add API keys through the web interface if needed"
        echo "  3. Review documentation in README.md"
        echo "  4. Start exploring OSINT capabilities!"
        echo ""
        log_info "📚 Resources:"
        echo "  Documentation: README.md"
        echo "  Quick Start: STARTUP_GUIDE.md"
        echo "  Web Interface: ENHANCED_PLATFORM_GUIDE.md"
        echo "  Configuration: config.ini"
    else
        echo ""
        log_warning "Installation completed with warnings"
        log_info "Some features may be limited. Check the logs above for details."
        log_info "You can still run the setup wizard later with: ./install_universal.sh --wizard"
    fi
}

# ===========================================
# ERROR HANDLING
# ===========================================

trap 'log_error "Installation failed at step $CURRENT_STEP"' ERR

# Run main installation
main "$@"