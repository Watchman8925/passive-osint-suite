# Passive OSINT Suite 🔍

[![Production Ready](https://img.shields.io/badge/status-production--ready-success)](https://github.com/Watchman8925/passive-osint-suite)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](docker-compose.yml)

A **comprehensive, production-ready** Open Source Intelligence (OSINT) gathering suite with enterprise-grade security, anonymity, and operational security features. Built for professional intelligence analysts, security researchers, and investigators who need reliable, auditable, and anonymous intelligence gathering capabilities.

## ⚡ Recent Updates (v2.0.0)

**Critical security improvements and code quality enhancements have been implemented:**

✅ **Security Hardening**
- Eliminated hardcoded secrets - all secrets now required via environment variables
- Implemented comprehensive input validation (XSS, SQL injection, command injection prevention)
- Added rate limiting on all API endpoints
- Secured development endpoints with strict environment checks
- Enforced strong passwords in Docker configuration

✅ **Reliability Improvements**
- Implemented async file I/O (non-blocking operations)
- Added detailed health check endpoints with service connectivity testing
- Created React error boundaries for graceful error handling
- Fixed silent failure patterns throughout the codebase

✅ **Code Quality**
- Added 5 new security dependencies (slowapi, aiofiles, structlog, pybreaker, pyjwt)
- Implemented environment-based configuration for frontend API URLs
- Created comprehensive documentation (Security Guide, Setup Guide, Review Summary)

**📚 New Documentation:**
- [QUICK_START.md](QUICK_START.md) - Get running in 5 minutes
- [SECURITY_GUIDE.md](SECURITY_GUIDE.md) - Security best practices & deployment checklist
- [SETUP_GUIDE.md](SETUP_GUIDE.md) - Comprehensive installation & deployment guide
- [CODE_REVIEW_SUMMARY.md](CODE_REVIEW_SUMMARY.md) - Detailed review of all changes

**⚠️ Breaking Changes:**
- `.env` file configuration is now **required** (app won't start without proper secrets)
- Docker passwords must be explicitly set (no weak defaults)
- Frontend needs rebuild after environment variable changes

See [CODE_REVIEW_SUMMARY.md](CODE_REVIEW_SUMMARY.md) for complete details.

---

## 🚀 Quick Start

### Automated Setup (Recommended)

```bash
# 1. Run the comprehensive setup script
./setup.sh

# 2. Start the OSINT suite
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
