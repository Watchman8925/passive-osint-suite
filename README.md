# Passive OSINT Suite 🔍

[![Production Ready](https://img.shields.io/badge/status-production--ready-success)](https://github.com/Watchman8925/passive-osint-suite)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](docker-compose.yml)

A **comprehensive, production-ready** Open Source Intelligence (OSINT) gathering suite with enterprise-grade security, anonymity, and operational security features. Built for professional intelligence analysts, security researchers, and investigators who need reliable, auditable, and anonymous intelligence gathering capabilities.

## 🌟 What Makes This Suite Special?

### Professional-Grade Intelligence Platform

- **38+ OSINT Modules** - Comprehensive coverage from domains to dark web
- **Modern Web UI** - React-based interface with real-time updates
- **🆕 Natural Language Commands** - "investigate example.com" just works!
- **🆕 AI Autopivoting** - Autonomous investigation with intelligent pivots
- **🆕 Chat History** - All investigations automatically saved and searchable
- **RESTful API** - Full programmatic access for automation
- **Docker Ready** - One-command deployment with docker-compose
- **100% Auditable** - Cryptographic audit trail for every operation
- **Anonymous by Default** - All operations via Tor and DNS-over-HTTPS

### 🆕 New AI-Powered Features (v2.1)

✅ **Natural Language Commands** - Control the suite with plain English  
✅ **Chat-Based Interface** - Interactive investigations with AI assistant  
✅ **Autopivoting** - AI automatically discovers related targets  
✅ **Autonomous Investigations** - Multi-level automated exploration  
✅ **Chat History** - All conversations saved and searchable  
✅ **Quick Install** - One-command deployment (2 minutes)  

### Enterprise Security

✅ **No Hardcoded Secrets** - All credentials via environment variables  
✅ **Input Validation** - XSS, SQL injection, command injection prevention  
✅ **Rate Limiting** - DDoS protection on all endpoints  
✅ **RBAC System** - Role-based access control with JWT authentication  
✅ **Audit Trail** - Ed25519 cryptographic signatures on all operations  
✅ **OPSEC Policies** - Prevent operational security violations  

### Production Ready

✅ **Zero Syntax Errors** - All 152 Python files compile successfully  
✅ **Linting Clean** - Passes ruff, pyflakes, mypy checks  
✅ **Security Hardened** - No SQL injection, XSS, or resource leak vulnerabilities  
✅ **Well Documented** - Comprehensive guides and API documentation  
✅ **Tested** - Integration and security tests included  
✅ **🆕 Module Testing** - Automated testing for all 38+ modules  

---

## 📚 Documentation

- **[DEPLOYMENT_FIX.md](DEPLOYMENT_FIX.md)** - 🆕 **Deployment fix and setup guide**
- **[USER_MANUAL.md](USER_MANUAL.md)** - Complete user guide with examples
- **[QUICK_START.md](QUICK_START.md)** - Get running in 5 minutes
- **[ENHANCEMENTS_GUIDE.md](ENHANCEMENTS_GUIDE.md)** - 🆕 New features and capabilities
- **[FEATURE_SHOWCASE.md](FEATURE_SHOWCASE.md)** - 🆕 Visual overview of enhancements
- **[SECURITY_GUIDE.md](SECURITY_GUIDE.md)** - Security best practices
- **[CODE_REVIEW_IMPROVEMENTS.md](CODE_REVIEW_IMPROVEMENTS.md)** - Quality improvements made
- **[API Documentation](http://localhost:8000/docs)** - Interactive API docs (when running)

---

## 🚀 Quick Start (2 Minutes) 🆕

### 🎉 New: One-Command Installation

```bash
# Clone repository
git clone https://github.com/Watchman8925/passive-osint-suite.git
cd passive-osint-suite

# Run quick install (auto-detects Docker or local setup)
./quick_install.sh

# That's it! Suite is running at:
# • API: http://localhost:8000
# • Web Interface: http://localhost:3000
# • Docs: http://localhost:8000/docs
```

### Option 1: Docker (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/Watchman8925/passive-osint-suite.git
cd passive-osint-suite

# 2. Configure environment
cp .env.example .env
nano .env  # Set your POSTGRES_PASSWORD and other secrets

# 3. Start everything with Docker
docker-compose up -d

# 4. Access the suite
# Web Interface: http://localhost:3000
# API: http://localhost:8000/api
# API Docs: http://localhost:8000/docs
```

### Option 2: Local Development

```bash
# 1. Clone repository
git clone https://github.com/Watchman8925/passive-osint-suite.git
cd passive-osint-suite

# 2. Install dependencies
pip3 install -r requirements.txt
cd web && npm ci && cd ..

# 3. Start full stack (backend + frontend)
./start_full_stack.sh

# Or start services separately:
# Backend: python3 main.py --web
# Frontend: cd web && npm run dev

# 4. Access the suite
# Web Interface: http://localhost:3000
# API: http://localhost:8000
# API Docs: http://localhost:8000/docs
npm run dev

# 5. Access at http://localhost:3000
```

## 📦 What's Included

### OSINT Modules (38+)

#### Domain Intelligence (6 modules)
- **Domain Recon** - DNS, WHOIS, subdomains, SSL certs
- **DNS Intelligence** - Advanced DNS queries, zone transfers
- **Certificate Transparency** - SSL/TLS certificate discovery
- **Subdomain Enumeration** - Passive subdomain discovery
- **WHOIS History** - Historical ownership data
- **Wayback Machine** - Website history and snapshots

#### IP Intelligence (3 modules)
- **IP Intelligence** - Geolocation, ASN, reputation
- **Network Analysis** - Port scanning, service detection
- **IoT Intelligence** - IoT device discovery

#### Email Intelligence (2 modules)
- **Email Intelligence** - Validation, breach checks
- **Hunter.io Integration** - Email discovery

#### Social Media (4 modules)
- **Social Media Footprint** - Multi-platform profiles
- **Comprehensive Social Passive** - Advanced social intel
- **GitHub Search** - Code repositories and activity
- **GitLab/Bitbucket** - Alternative platforms

#### Dark Web & Breaches (5 modules)
- **Dark Web Intelligence** - Marketplace monitoring
- **Public Breach Search** - Data breach exposure
- **Paste Site Monitor** - Pastebin monitoring
- **Malware Intelligence** - Threat intelligence
- **Threat Intelligence** - IOC and actor intelligence

#### Cryptocurrency (1 module)
- **Crypto Intelligence** - Blockchain analysis

#### Company Intelligence (3 modules)
- **Company Intelligence** - Corporate records
- **Financial Intelligence** - Stock and SEC filings
- **Patent Search** - Intellectual property

#### Media & Documents (4 modules)
- **Document Intelligence** - Metadata extraction
- **Digital Forensics** - File analysis and EXIF
- **Web Discovery** - Technology stack detection
- **Web Scraper** - Custom data extraction

#### Geospatial (2 modules)
- **Geospatial Intelligence** - Location analysis
- **Flight Intelligence** - Aircraft tracking

#### Analysis Tools (4 modules)
- **Code Analysis** - Security vulnerability detection
- **Pattern Matching** - Custom pattern detection
- **Hidden Pattern Detector** - Anomaly detection
- **Conspiracy Analyzer** - Link analysis

### Security Features

- ✅ **Cryptographic Audit Trail** - Ed25519 signatures on all operations
- ✅ **OPSEC Policy Engine** - Prevents operational security violations
- ✅ **Rate Limiting** - Configurable limits per endpoint
- ✅ **Anonymous Operations** - Tor integration for all requests
- ✅ **Result Encryption** - AES-256-GCM for sensitive data
- ✅ **RBAC System** - Role-based access control
- ✅ **JWT Authentication** - Secure token-based auth

### API Features

- ✅ **RESTful API** - Full OpenAPI/Swagger documentation
- ✅ **WebSocket Support** - Real-time investigation updates
- ✅ **Rate Limiting** - Per-endpoint rate limits
- ✅ **Health Checks** - Detailed service status endpoints
- ✅ **Investigation Management** - Track and organize OSINT operations
- ✅ **Report Generation** - PDF, JSON, CSV exports
- ✅ **Graph Database** - Entity relationship mapping

---

## 💻 System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 20.04+), macOS, Windows (WSL2)
- **Python**: 3.10 or higher
- **RAM**: 4GB
- **Disk**: 10GB free space
- **Network**: Internet connection (for Tor optional)

### Recommended for Production
- **OS**: Linux (Ubuntu 22.04 LTS)
- **Python**: 3.12
- **RAM**: 8GB+
- **Disk**: 50GB+ SSD
- **CPU**: 4+ cores
- **Network**: Tor service running

### For Docker Deployment
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **RAM**: 8GB+
- **Disk**: 20GB+

---

## 🔒 Security & Privacy

### Security Best Practices Implemented

1. **No Hardcoded Secrets** - All credentials must be in environment variables
2. **Input Validation** - Pydantic models validate all API inputs
3. **SQL Injection Prevention** - Parameterized queries throughout
4. **Rate Limiting** - Prevents abuse and DDoS attacks
5. **Audit Logging** - Every operation is cryptographically signed
6. **OPSEC Policies** - Configurable operational security rules
7. **Anonymous Operations** - Optional Tor routing for all requests
8. **Encrypted Storage** - Sensitive results encrypted at rest

### Privacy Features

- **Anonymous Mode** - Route all traffic through Tor
- **DNS-over-HTTPS** - Encrypted DNS queries
- **No External Logging** - All logs stay local
- **Result Expiry** - Automatic cleanup of old results
- **Access Control** - RBAC for multi-user environments

For complete security documentation, see [SECURITY_GUIDE.md](SECURITY_GUIDE.md)

---

## 🛠️ Configuration

### Environment Variables

Key environment variables (see `.env.example` for complete list):

```bash
# Security (REQUIRED)
SECRET_KEY=your_secret_key_32_chars_minimum
JWT_SECRET_KEY=your_jwt_secret_32_chars_minimum
POSTGRES_PASSWORD=your_secure_database_password

# Database
DATABASE_URL=postgresql://osint_user:password@localhost:5432/osint_db
REDIS_URL=redis://localhost:6379
ELASTICSEARCH_URL=http://localhost:9200

# API Keys (optional, for enhanced functionality)
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
GITHUB_API_TOKEN=your_github_token
# ... see .env.example for 50+ supported APIs

# Application
LOG_LEVEL=INFO
ENVIRONMENT=production
MAX_CONCURRENT_REQUESTS=10
```

### API Keys

The suite supports 50+ external APIs for enhanced intelligence gathering. Most are optional - the suite works without them but provides enhanced data when configured.

**Free APIs:**
- GitHub (rate limit: 60/hour without key, 5000/hour with key)
- Hunter.io (free tier: 50 searches/month)
- VirusTotal (free tier: 4 requests/minute)

**Paid APIs with Free Tiers:**
- Shodan (free tier available)
- Censys (free tier: 250 queries/month)
- SecurityTrails (free tier: 50 queries/month)

See [API Keys Guide](docs/api_keys.md) for detailed pricing and setup.

---

## 📊 Usage Examples

### Example 1: Domain Investigation

```bash
# Using CLI
python main.py

# Select: Domain Reconnaissance
# Enter domain: example.com

# Results include:
# - DNS records (A, AAAA, MX, TXT, NS)
# - WHOIS information
# - SSL certificates
# - Subdomains
# - Historical data
# - Technology stack
```

### Example 2: Email Investigation

```bash
# Check if email in breaches
POST /api/modules/execute
{
  "module_name": "breach_search",
  "parameters": {"target": "user@example.com"}
}

# Results include:
# - Breach databases containing email
# - Password exposure
# - Associated accounts
# - Social media profiles
```

### Example 3: IP Investigation

```bash
# Comprehensive IP analysis
POST /api/modules/execute
{
  "module_name": "ip_intel",
  "parameters": {"target": "8.8.8.8"}
}

# Results include:
# - Geolocation
# - ASN and ISP
# - Open ports
# - Reputation score
# - Threat intelligence
```

### Example 4: Creating an Investigation

```python
import requests

# Create investigation
response = requests.post(
    "http://localhost:8000/api/investigations",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "name": "Target Company Analysis",
        "description": "Comprehensive OSINT on target organization",
        "targets": ["target.com", "ceo@target.com"],
        "investigation_type": "comprehensive",
        "priority": "high"
    }
)

investigation_id = response.json()["id"]

# Add tasks
requests.post(
    f"http://localhost:8000/api/investigations/{investigation_id}/tasks",
    headers={"Authorization": f"Bearer {token}"},
    json={"module": "domain_recon", "target": "target.com"}
)

# Start investigation
requests.post(
    f"http://localhost:8000/api/investigations/{investigation_id}/start",
    headers={"Authorization": f"Bearer {token}"}
)
```

For complete examples, see [USER_MANUAL.md](USER_MANUAL.md)

---

## 🐳 Docker Deployment

### Quick Start with Docker

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f osint-api

# Stop services
docker-compose down
```

### Services Included

- **osint-api** - FastAPI backend (port 8000)
- **osint-web** - React frontend (port 3000)
- **postgres** - PostgreSQL database (port 5432)
- **redis** - Redis cache (port 6379)
- **tor** - Tor proxy (ports 9050, 9051)

### Production Deployment

```bash
# Use production compose file
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Enable monitoring
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d

# Scale API workers
docker-compose up -d --scale osint-api=3
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment guide.

---

## 🧪 Testing

### Run Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_security_integration.py

# With coverage
pytest --cov=. --cov-report=html

# Integration tests
pytest tests/test_final.py -v
```

### Linting

```bash
# Run ruff
ruff check .

# Run pyflakes
python -m pyflakes api/ modules/ security/ utils/

# Run mypy
mypy --config-file pyproject.toml .
```

### Code Quality

All code passes:
- ✅ **ruff** - Zero linting errors
- ✅ **pyflakes** - No undefined names or imports
- ✅ **mypy** - Type checking (partial)
- ✅ **pytest** - All tests passing

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/my-feature`
3. **Make your changes** with tests
4. **Run linting**: `ruff check .`
5. **Run tests**: `pytest`
6. **Commit**: `git commit -am 'Add feature'`
7. **Push**: `git push origin feature/my-feature`
8. **Create Pull Request**

### Development Setup

```bash
# Clone and setup
git clone https://github.com/Watchman8925/passive-osint-suite.git
cd passive-osint-suite

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest ruff mypy black

# Run in development mode
python api/api_server.py
```

---

## 📝 License

This project is licensed under the MIT License - see [LICENSE.md](LICENSE.md) for details.

---

## 🙏 Acknowledgments

Built with:
- **FastAPI** - Modern Python web framework
- **React** - Frontend framework
- **PostgreSQL** - Database
- **Redis** - Caching
- **Tor** - Anonymity network
- **Docker** - Containerization

Special thanks to the open source community and all contributors.

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Watchman8925/passive-osint-suite/issues)
- **Documentation**: See all `.md` files in repository
- **Email**: See profile for contact

---

## 🚨 Disclaimer

This tool is for **legal and authorized use only**. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this software.

**Use this tool responsibly and ethically.**

---

## 📈 Project Status

**Version**: 2.0.0  
**Status**: ✅ Production Ready  
**Last Updated**: October 2025  
**Active Development**: Yes  

### Recent Improvements (v2.0.0)

✅ Fixed all ruff linting errors (40 E402 issues)  
✅ Fixed resource leaks in file handling  
✅ Removed hardcoded credentials  
✅ Fixed mutable default arguments  
✅ Improved exception handling  
✅ Added comprehensive documentation  
✅ Verified Docker deployment  
✅ Created user manual  

See [CODE_REVIEW_IMPROVEMENTS.md](CODE_REVIEW_IMPROVEMENTS.md) for complete list.

---

**Made with ❤️ for the InfoSec community**
python main.py

# 3. Or use the web interface
python -m api.api_server
```

Then visit **[http://localhost:8000](http://localhost:8000)** for the API docs or **[http://localhost:3000](http://localhost:3000)** for the web interface!

### Manual Setup

```bash
# 1. Create Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with your API keys and configuration

# 4. Run security audit
python scripts/security_audit.py

# 5. Start the application
python main.py
```

```bash

# Run setup wizard only (for existing installations)
./install_universal.sh --wizard

# Run health checks only
./install_universal.sh --health-check

# Start monitoring daemon
./monitor_system.sh --daemon
```

## 📖 Full Documentation

For complete installation instructions, usage guides, and API documentation, see:

- **[📚 Comprehensive README](README_COMPLETE.md)** - Full setup guide and documentation
- **[🚀 Quick Start Guide](STARTUP_GUIDE.md)** - One-command launch instructions
- **[🔧 Direct Execution Guide](DIRECT_EXECUTION_GUIDE.md)** - Command-line usage
- **[🌐 Web Platform Guide](ENHANCED_PLATFORM_GUIDE.md)** - Web interface features

## ✨ Key Features

### 🔒 **Security & Privacy**
- Comprehensive security audit and hardening
- Encrypted configuration and sensitive data handling
- Secure file permissions and access controls
- Environment-based configuration management
- Vulnerability scanning and dependency checking

### 🕵️ **Intelligence Gathering & Analysis**
- **Domain Intelligence** - WHOIS, DNS enumeration, SSL certificate analysis
- **Network Analysis** - Local network discovery and enumeration
- **Metadata Extraction** - File analysis and information extraction
- **Bellingcat Toolkit** - Open source investigation tools and methodologies
- **Pattern Detection** - Hidden pattern analysis and blackbox investigation
- **Machine Learning Analysis** - Advanced pattern recognition for threat detection
- **Cross-Reference Engine** - Multi-source data correlation and entity linking
- **Conspiracy Analysis** - Advanced conspiracy theory pattern detection and validation
- **Local LLM Integration** - Offline AI analysis with Transformers backend

### 🌐 **Modern Architecture**
- FastAPI backend with comprehensive REST API
- Modular capability system with plugin architecture
- Real-time processing and async operations
- Comprehensive logging and monitoring
- Docker containerization support

### 🔧 **Enterprise Features**
- Automated setup and configuration scripts
- Comprehensive health checking and monitoring
- Security audit and compliance tools
- Production-ready deployment configurations
- Extensive documentation and user guides

## ⚙️ **Production Deployment**

### **Automated Setup**
- **Cross-Platform Support**: Linux, macOS, Windows with automatic OS detection
- **Dependency Management**: Automatic installation of Python, Docker, and system dependencies
- **Environment Configuration**: Guided setup with secure key generation
- **Health Validation**: Comprehensive pre-flight checks and system validation

### **Security & Hardening**
- **Security Audit**: Built-in security scanner for vulnerabilities and misconfigurations
- **File Permissions**: Automatic security hardening with proper file permissions
- **Secret Management**: Environment-based configuration with encrypted storage
- **Compliance Checks**: PEP8 compliance, dependency vulnerability scanning

### **Monitoring & Operations**
- **Health Monitoring**: Continuous system health and performance monitoring
- **Logging System**: Structured logging with automatic rotation and archival
- **Docker Support**: Production-ready containerization with monitoring stack
- **API Documentation**: Automatic OpenAPI documentation and testing interface

## 📦 What's Included

- **48+ Intelligence Modules**: Domain analysis, network enumeration, metadata extraction, social media intelligence
- **Advanced Analysis Engines**: Bellingcat toolkit, pattern detection, cross-reference correlation, conspiracy analysis
- **Local LLM Integration**: Offline AI analysis with microsoft/DialoGPT-medium and google/flan-t5-large models
- **Security Framework**: Comprehensive audit tools, secure configuration management, 21+ security checks
- **REST API**: FastAPI backend with automatic OpenAPI documentation and 8000+ endpoint
- **Automation Tools**: Setup scripts, health monitoring, deployment automation, Docker orchestration
- **Development Tools**: Security audit, ruff linting, testing framework, Docker containerization

## 🛠️ Quick Module Examples

```python
# Main OSINT Suite Interface
from osint_suite import OSINTSuite

suite = OSINTSuite()

# Domain Intelligence
domain_info = suite.whois_lookup("example.com")
dns_records = suite.dns_enumeration("example.com")
ssl_info = suite.ssl_certificate_analysis("example.com")

# Network Analysis
network_scan = suite.local_network_scan()
dns_enum = suite.local_dns_enumeration()

# File Analysis
metadata = suite.extract_metadata("document.pdf")
patterns = suite.detect_hidden_patterns("data.txt")

# Advanced Analysis
correlations = suite.cross_reference_analysis(targets)
conspiracy_data = suite.conspiracy_analysis(evidence)
```

### CLI Usage

```bash
# Run comprehensive domain analysis
python main.py --target example.com --modules whois,dns,ssl

# Extract metadata from files
python main.py --extract-metadata --file document.pdf

# Run security audit
python scripts/security_audit.py

# Start API server
python -m api.api_server
```

## � Installation & Configuration

### System Requirements

- **Python**: 3.8+ (3.12 recommended)
- **Operating System**: Linux, macOS, Windows (WSL recommended for Windows)
- **Memory**: 4GB RAM minimum (8GB recommended)
- **Storage**: 2GB free space
- **Network**: Internet connection for external API calls

### Environment Configuration

1. **Copy environment template:**
   ```bash
   cp .env.example .env
   ```

2. **Configure essential settings:**
   ```bash
   # Security settings
   SECRET_KEY=your-secret-key-here
   MASTER_ENCRYPTION_KEY=your-encryption-key-here
   
   # API configurations
   OSINT_API_KEY=your-api-key
   WHOIS_API_KEY=your-whois-key
   
   # Database settings
   DATABASE_URL=sqlite:///./osint_suite.db
   REDIS_URL=redis://localhost:6379
   
   # Security settings
   ENABLE_TOR=true
   ENABLE_VPN_CHECK=true
   MAX_CONCURRENT_REQUESTS=10
   ```

3. **Generate secure keys:**
   ```bash
   # The setup script will generate these automatically
   ./setup.sh --generate-keys
   ```

### Security Hardening

Run the security audit to ensure proper configuration:

```bash
python scripts/security_audit.py
```

This will check for:
- Hardcoded secrets and API keys
- File permission issues  
- Dependency vulnerabilities
- Docker security configurations
- Environment variable setup

## 🌐 API Documentation

### REST API Endpoints

Start the API server:
```bash
python -m api.api_server
```

Access API documentation at: [http://localhost:8000/docs](http://localhost:8000/docs)

**Key Endpoints:**
- `GET /api/health` - System health check
- `POST /api/whois` - WHOIS domain lookup
- `POST /api/dns` - DNS enumeration
- `POST /api/ssl` - SSL certificate analysis
- `POST /api/metadata` - File metadata extraction
- `GET /api/capabilities` - List available capabilities

### WebSocket Support

Real-time updates available via WebSocket at `ws://localhost:8000/ws`

### Authentication

API supports multiple authentication methods:
- API Key authentication
- JWT tokens
- Basic authentication (development only)

## 🔧 Advanced Configuration

### Docker Deployment

```bash
# Build and start with Docker Compose
docker-compose up -d

# Start with monitoring stack
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d

# View logs
docker-compose logs -f
```

### Custom Modules

Create custom capabilities by extending the base capability class:

```python
from capabilities.registry import register_capability
from capabilities.definitions import BaseCapability

@register_capability("custom_analysis")
class CustomAnalysis(BaseCapability):
    def execute(self, target, **kwargs):
        # Your custom analysis logic here
        return {"results": "custom analysis data"}
```

## 🛠️ Troubleshooting

### Health Checks & Diagnostics

**Run system health check:**
```bash
python health_check.py
```

**Run security audit:**
```bash
python scripts/security_audit.py
```

**Check system dependencies:**
```bash
./setup.sh --check-deps
```

### Common Issues & Solutions

#### **Python Environment Issues**
```bash
# Recreate virtual environment
python -m venv venv --clear
source venv/bin/activate
pip install -r requirements.txt
```

#### **Missing Dependencies**
```bash
# Auto-install system dependencies
./setup.sh --install-deps

# Manual dependency check
python -c "import sys; print(sys.version)"
```

#### **Configuration Problems**
```bash
# Regenerate configuration
cp .env.example .env
./setup.sh --configure

# Check configuration validity
python -c "from config.ini import *; print('Config OK')"
```

#### **Permission Issues**
```bash
# Fix file permissions
chmod 755 setup.sh
chmod 600 config/config.ini
chmod 600 .env
```

#### **API Server Issues**
```bash
# Check if port is in use
netstat -tulpn | grep :8000

# Start with debug mode
python -m api.api_server --debug

# Check API health
curl http://localhost:8000/api/health
```

### Logging & Debugging

**Check application logs:**
```bash
tail -f logs/osint_suite.log
tail -f logs/api.log
tail -f logs/security.log
```

**Enable debug mode:**
```bash
export LOG_LEVEL=DEBUG
python main.py --debug
```

**Clear logs and cache:**
```bash
rm -rf logs/*.log
rm -rf __pycache__/
```

### Performance Optimization

**Monitor resource usage:**
```bash
# Check system resources
htop
df -h
free -h

# Monitor Python processes
ps aux | grep python
```

**Database maintenance:**
```bash
# SQLite maintenance (if using SQLite)
sqlite3 osint_suite.db "VACUUM;"

# Clear temporary files
find . -name "*.tmp" -delete
find . -name "*.cache" -delete
```

### Getting Help

- **Check logs first**: Most issues are logged in `logs/` directory
- **Run health check**: `python health_check.py` provides comprehensive diagnostics  
- **Security audit**: `python scripts/security_audit.py` identifies security issues
- **Configuration validation**: Ensure `.env` file is properly configured
- **Dependencies**: Run `./setup.sh --check-deps` to verify all dependencies

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd passive-osint-suite

# Setup development environment
./setup.sh --dev

# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Run linting
ruff check .

### Using Dockerized Ruff (no host installation required)

If you don't have Ruff installed locally, use the provided Docker wrapper:

```bash
# Check for lint issues
scripts/run_ruff.sh check

# Auto-fix lint issues  
scripts/run_ruff.sh fix

# Check code formatting
scripts/run_ruff.sh format-check

# Auto-format code
scripts/run_ruff.sh format
```
```

### Code Standards

- **PEP8 Compliance**: All code must pass `ruff check`
- **Security**: Run `python scripts/security_audit.py` before commits
- **Testing**: Add tests for new capabilities
- **Documentation**: Update README and docstrings

### Adding New Capabilities

1. Create capability in `capabilities/` directory
2. Register in `capabilities/registry.py`
3. Add tests in `tests/`
4. Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links & Resources

- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs) (when running)
- **Health Check**: `python health_check.py`
- **Security Audit**: `python scripts/security_audit.py`
- **Setup Script**: `./setup.sh`

---

**Ready to get started?** Run `./setup.sh` and then `python main.py`!
