# Autonomous OSINT Suite

A comprehensive, autonomous Open Source Intelligence (OSINT) gathering suite with enterprise-grade security, anonymity, and operational security features. Now enhanced with **RapidAPI integrations**, **free tools**, **pre-seeded databases**, and a **modern web interface**.

## 🚀 Overview

This suite provides a complete framework for secure, anonymous OSINT operations with advanced features inspired by professional investigative journalism and intelligence gathering practices.

## ✨ Key Features

### 🔒 **Security & Anonymity**

- **Tor Integration**: All traffic routed through Tor SOCKS5 proxy with circuit hygiene
- **DNS over HTTPS (DoH)**: Secure DNS resolution via Tor with caching
- **Query Obfuscation**: Decoy queries, timing randomization, and anti-fingerprinting
- **Anonymity Grid**: Cooperative query mixing and traffic obfuscation

### 🛡️ **Operational Security (OPSEC)**

- **Policy Engine**: Runtime policy enforcement with policy-as-code DSL
- **Immutable Audit Trail**: ED25519-signed, tamper-evident operation logs
- **Result Encryption**: AES-256-GCM encryption with RSA key wrapping
- **Secrets Management**: Secure API key storage with OS keyring integration

### 🕵️ **Intelligence Gathering**

- **Bellingcat Toolkit**: Entity extraction, web reconnaissance, timeline analysis
- **Media Forensics**: EXIF analysis, steganography detection, image comparison
- **Network Intelligence**: Passive infrastructure analysis, CDN detection
- **Domain/Email/IP Intelligence**: Comprehensive reconnaissance modules
- **RapidAPI Integration**: 15+ free-tier services for enhanced intelligence gathering
- **Pre-seeded Databases**: Government and open source intelligence databases (no API keys required)
- **Free Tools**: Local analysis tools with zero external dependencies

### 🌐 **Modern Web Interface**

- **React/Vite Frontend**: Modern, responsive web application
- **Real-time Dashboard**: Live investigation monitoring and progress tracking
- **AI-Powered Analysis**: Integrated local LLM and cloud AI capabilities
- **Data Visualization**: Interactive charts, graphs, and geographic mapping
- **Investigation Management**: Case organization and workflow management
- **Export System**: Multiple format support (JSON, CSV, PDF, Excel)

### 🔧 **Operational Tools**

- **CLI Tools**: Complete command-line interfaces for all components
- **Batch Processing**: Automated query processing and result aggregation
- **Monitoring**: Real-time statistics and health monitoring
- **Integration APIs**: Easy integration with existing workflows

## 📁 Project Structure

```
passive_osint_suite/
├── Core Security Infrastructure
│   ├── transport.py              # Tor-proxied HTTP client
│   ├── tor_control.py           # Tor circuit management
│   ├── doh_client.py            # DNS over HTTPS via Tor
│   ├── query_obfuscation.py     # Anti-fingerprinting system
│   └── secrets_manager.py       # Secure secrets storage
│
├── Enterprise Security
│   ├── audit_trail.py           # Immutable audit logging
│   ├── result_encryption.py     # Result encryption system
│   ├── opsec_policy.py         # Policy enforcement engine
│   └── anonymity_grid.py       # Cooperative anonymity system
│
├── Intelligence Modules
│   ├── bellingcat_toolkit.py   # Investigative journalism tools
│   ├── media_forensics.py      # Media analysis and forensics
│   ├── network_intelligence.py # Network infrastructure analysis
│   ├── domain_recon.py         # Domain intelligence
│   ├── email_intel.py          # Email intelligence
│   ├── ip_intel.py             # IP address intelligence
│   ├── company_intel.py        # Corporate intelligence
│   ├── crypto_intel.py         # Cryptocurrency intelligence
│   ├── flight_intel.py         # Flight tracking intelligence
│   ├── rapidapi_osint.py       # RapidAPI integration (15+ services)
│   ├── preseeded_databases.py  # Government/open source databases
│   ├── free_tools.py           # Local analysis tools (no dependencies)
│   └── search_engine_dorking.py # Enhanced Google dorking (4 engines)
│
├── Web Application
│   ├── web/                    # React/Vite frontend application
│   │   ├── src/               # React components and pages
│   │   ├── package.json       # Node.js dependencies
│   │   └── vite.config.ts     # Vite configuration
│   └── api/                   # FastAPI backend server
│       └── api_server.py     # REST API with WebSocket support
│
├── Command Line Tools
│   ├── audit_cli.py            # Audit trail management
│   ├── result_encryption_cli.py # Result encryption CLI
│   ├── opsec_cli.py            # OPSEC policy management
│   ├── anonymity_cli.py        # Anonymity grid control
│   └── secrets_cli.py          # Secrets management CLI
│
├── Demonstrations
│   ├── demo_complete.py        # Complete suite demonstration
│   ├── demo_audit.py          # Audit trail demo
│   ├── demo_opsec.py          # OPSEC policy demo
│   └── demo_obfuscation.py    # Query obfuscation demo
│
└── Core Utilities
    ├── osint_utils.py          # Core utilities and integration
    ├── osint_suite.py         # Main suite interface
    └── passive_search.py      # Search orchestration
```

## 🛠️ Installation & Setup

### Prerequisites

```bash
# Install system dependencies
sudo apt update
sudo apt install tor python3-pip nodejs npm redis-server elasticsearch

# Start required services
sudo systemctl start tor redis-server elasticsearch
sudo systemctl enable tor redis-server elasticsearch
```

### One-Command Setup (Recommended)

For the complete setup with web interface:

```bash
# Run the automated setup script
./start_simple.sh
```

This script automatically:
- ✅ Creates Python virtual environment
- ✅ Installs all Python dependencies
- ✅ Sets up Node.js environment for web app
- ✅ Builds the React frontend
- ✅ Configures API keys and secrets
- ✅ Starts both API server and web interface

### Manual Setup

If you prefer manual setup:

```bash
# 1. Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set up web application
cd web
npm install
npm run build
cd ..

# 4. Configure the application
cp config.ini.example config.ini
mkdir -p logs output

# 5. Initialize secrets manager
python -c "from security.secrets_manager import init_keyring; init_keyring()"
```

### Python Dependencies

```bash
# Core OSINT dependencies
pip install requests beautifulsoup4 dnspython validators

# Security and anonymity
pip install cryptography keyring pycryptodome httpx-socks

# Web framework
pip install fastapi uvicorn pydantic

# Enhanced modules (new)
pip install openai redis elasticsearch websockets
pip install transformers torch scikit-learn
pip install neo4j py2neo
```

### Web Application Dependencies

```bash
# Install Node.js dependencies
cd web
npm install

# Build the frontend
npm run build
```

### Configuration

```bash
# Edit configuration file
nano config.ini

# Key settings to configure:
# - API keys for various services
# - Tor proxy settings
# - Logging configuration
# - Database connections (Redis, Elasticsearch)
```

## 🌐 Web Application Setup Guide

### Step 1: System Prerequisites

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required system packages
sudo apt install -y \
    tor \
    redis-server \
    elasticsearch \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    curl \
    git \
    build-essential

# Start and enable services
sudo systemctl start tor redis-server elasticsearch
sudo systemctl enable tor redis-server elasticsearch

# Verify installations
python3 --version
node --version
npm --version
redis-cli ping
curl -X GET "localhost:9200"
```

### Step 2: Clone and Setup Repository

```bash
# Clone the repository (if not already done)
git clone <repository-url> osint-suite
cd osint-suite

# Make scripts executable
chmod +x *.sh
chmod +x scripts/*.sh
```

### Step 3: Python Environment Setup

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
python -c "import fastapi, uvicorn, redis, elasticsearch; print('✅ Python dependencies installed')"
```

### Step 4: Web Application Setup

```bash
# Navigate to web directory
cd web

# Install Node.js dependencies
npm install

# Build the production application
npm run build

# Verify build
ls -la dist/
# Should see: index.html, assets/, etc.

# Return to root directory
cd ..
```

### Step 5: Configuration Setup

```bash
# Copy configuration template
cp config.ini.example config.ini

# Edit configuration (optional - defaults should work)
nano config.ini

# Create required directories
mkdir -p logs output investigations evidence

# Initialize secrets manager
python -c "
from security.secrets_manager import init_keyring
try:
    init_keyring()
    print('✅ Secrets manager initialized')
except Exception as e:
    print(f'⚠️  Secrets manager init failed: {e}')
"
```

### Step 6: API Key Configuration (Optional)

The suite works without API keys, but you can enhance it with:

```bash
# Set up API keys (optional)
python -c "
from security.secrets_manager import store_api_key
# Add your API keys here if desired
# store_api_key('openai', 'your-openai-key')
# store_api_key('rapidapi', 'your-rapidapi-key')
print('API key setup complete')
"
```

### Step 7: Test the Setup

```bash
# Test Python imports
python -c "
try:
    from modules import get_module
    rapidapi = get_module('rapidapi_osint')
    db = get_module('preseeded_databases')
    tools = get_module('free_tools')
    dorking = get_module('search_engine_dorking')
    print('✅ All enhanced modules loaded successfully')
except Exception as e:
    print(f'❌ Module loading failed: {e}')
"

# Test web app build
cd web
npm run type-check
cd ..
```

### Step 8: Start the Application

#### Option A: One-Command Startup (Recommended)

```bash
# Start everything automatically
./start_simple.sh
```

#### Option B: Manual Startup

```bash
# Terminal 1: Start API server
source .venv/bin/activate
./start_api.sh

# Terminal 2: Start web application
cd web
npm run dev

# Or serve built version
npm run start
```

### Step 9: Access the Application

Once started, access:

- **Web Interface**: <http://localhost:3001>
- **API Backend**: <http://localhost:8001>
- **API Documentation**: <http://localhost:8001/docs>
- **Health Check**: <http://localhost:8001/health>

### Step 10: Verify Everything Works

```bash
# Test API endpoints
curl http://localhost:8001/health
curl http://localhost:8001/api/v1/modules

# Test enhanced modules via API
curl -X POST "http://localhost:8001/api/v1/modules/free_tools/analyze_url" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Test web interface
curl -I http://localhost:3001
```

## 🔧 Troubleshooting

### Common Issues

**1. Port Already in Use**
```bash
# Find process using port
sudo lsof -i :8001
sudo lsof -i :3001

# Kill process
sudo kill -9 <PID>
```

**2. Virtual Environment Issues**
```bash
# Recreate virtual environment
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**3. Node.js Build Issues**
```bash
cd web
rm -rf node_modules package-lock.json
npm install
npm run build
```

**4. Elasticsearch Connection Issues**
```bash
# Check Elasticsearch status
sudo systemctl status elasticsearch

# Restart if needed
sudo systemctl restart elasticsearch

# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"
```

**5. Redis Connection Issues**
```bash
# Check Redis status
sudo systemctl status redis-server

# Test connection
redis-cli ping
```

### Performance Tuning

```bash
# Increase file limits for Elasticsearch
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Configure JVM for Elasticsearch
sudo nano /etc/elasticsearch/jvm.options
# Set: -Xms2g -Xmx2g

# Restart services
sudo systemctl restart elasticsearch redis-server
```

## 📊 Monitoring and Logs

```bash
# View application logs
tail -f logs/osint_suite.log

# API server logs
tail -f api/logs/api_server.log

# Web application logs
cd web && tail -f logs/vite.log

# System resource usage
htop
df -h
free -h
```

## 🔄 Updates and Maintenance

```bash
# Update the suite
git pull origin main

# Update Python dependencies
source .venv/bin/activate
pip install -r requirements.txt --upgrade

# Update web dependencies
cd web
npm update
npm run build
cd ..

# Restart services
./start_simple.sh
```

## 🎯 Next Steps

1. **Explore the Web Interface**: Visit <http://localhost:3001> and try the different modules
2. **Configure API Keys**: Add RapidAPI and OpenAI keys for enhanced capabilities
3. **Set Up Monitoring**: Configure the monitoring dashboard
4. **Customize OPSEC Policies**: Adjust security policies for your use case
5. **Integrate with External Tools**: Connect with your existing workflow

The OSINT Suite is now ready for comprehensive intelligence gathering operations!
```

## 🚀 Quick Start

### Web Application (Recommended)

```bash
# Start the complete web application
./start_webapp.sh

# Access points:
# - Web Interface: http://localhost:3001
# - API Backend: http://localhost:8001
# - API Documentation: http://localhost:8001/docs
```

### Command Line Usage

```bash
# Activate virtual environment
source .venv/bin/activate

# Basic domain reconnaissance
python -c "from modules import get_module; dr = get_module('domain_recon'); print(dr.analyze('example.com'))"

# Use enhanced search engine dorking
python -c "from modules import get_module; dork = get_module('search_engine_dorking'); results = dork.dork('site:example.com filetype:pdf'); print(results)"

# Access RapidAPI services
python -c "from modules import get_module; rapid = get_module('rapidapi_osint'); results = rapid.comprehensive_person_search(email='test@example.com'); print(results)"

# Use free tools for local analysis
python -c "from modules import get_module; tools = get_module('free_tools'); metadata = tools.extract_file_metadata('README.md'); print(metadata)"
```

### API Server Only

```bash
# Start just the API server
./start_api.sh

# Access API documentation at http://localhost:8001/docs
```

## 📚 Enhanced Modules Guide

### 🔗 RapidAPI OSINT Module

Access 15+ free-tier RapidAPI services:

```python
from modules import get_module
rapidapi = get_module('rapidapi_osint')

# Person search across multiple services
results = rapidapi.comprehensive_person_search(
    email="target@example.com",
    name="John Doe"
)

# Company intelligence
company_data = rapidapi.comprehensive_company_search(
    domain="example.com"
)

# Threat intelligence
threats = rapidapi.threat_intelligence_lookup("malicious-domain.com")
```

### 🗄️ Pre-seeded Databases

Access government and open source databases (no API keys):

```python
from modules import get_module
db = get_module('preseeded_databases')

# Search CISA vulnerabilities
vulns = db.search_cisa_vulnerabilities("CVE-2023")

# FBI most wanted
wanted = db.search_fbi_most_wanted(name="John Doe")

# OFAC sanctions
sanctions = db.search_ofac_sanctions("target_name")

# Comprehensive search
results = db.comprehensive_search("target", ["vulnerabilities", "law_enforcement"])
```

### 🛠️ Free Tools Module

Local analysis without external dependencies:

```python
from modules import get_module
tools = get_module('free_tools')

# File metadata extraction
metadata = tools.extract_file_metadata("/path/to/file.pdf")

# URL security analysis
url_analysis = tools.analyze_url_locally("https://suspicious-site.com")

# Pattern extraction from text
patterns = tools.extract_patterns_from_text("Contact john@example.com or visit http://test.com")

# Local DNS resolution
dns_info = tools.local_dns_lookup("example.com")
```

### 🔍 Enhanced Search Engine Dorking

Advanced dorking across multiple engines:

```python
from modules import get_module
dorking = get_module('search_engine_dorking')

# Multi-engine search
results = dorking.dork("site:example.com password", engines=['duckduckgo', 'bing', 'yahoo'])

# Google dorking patterns
patterns = dorking.google_dorking_patterns("example.com", "email")

# Comprehensive dorking sweep
all_results = dorking.comprehensive_dorking_search("example.com")

# Subdomain enumeration
subdomains = dorking.passive_subdomain_enumeration("example.com")

# Exposed files detection
exposed = dorking.find_exposed_files("example.com")
```

```bash
# Create sample policies
python opsec_cli.py sample

# Test operations against policies
python opsec_cli.py test domain_lookup example.com

# View policy violations
python opsec_cli.py violations
```

### 4. Secure Storage

```bash
# Store API keys securely
python secrets_cli.py store shodan_api YOUR_API_KEY

# Encrypt investigation results
python result_encryption_cli.py encrypt results.json "Investigation XYZ"
```

## 🔐 Security Features

### Tor Integration

- All HTTP traffic routed through Tor SOCKS5 proxy
- Automatic circuit rotation and health monitoring
- Circuit isolation for different operation types

### DNS Security

- DNS over HTTPS (DoH) via Tor
- Multiple resolver support with failover
- Local caching with TTL respect

### Query Obfuscation

- Decoy query generation and mixing
- Timing randomization to prevent fingerprinting
- Batch processing with noise injection

### Audit & Compliance

- Cryptographically signed audit logs (ED25519)
- Hash-chained entries for tamper detection
- Comprehensive operation logging

## 🛡️ OPSEC Features

### Policy Engine

- Policy-as-code DSL for runtime enforcement
- Violation tracking and alerting
- Configurable actions (deny, warn, delay, approve)

### Result Protection

- AES-256-GCM encryption for sensitive results
- RSA key wrapping for operator control
- Burn-after-read and expiration controls

### Anonymity Grid

- Cooperative query mixing between nodes
- Decoy traffic generation
- Multi-hop query routing

## 📊 Monitoring & Statistics

### Real-time Monitoring

```bash
# View audit trail status
python audit_cli.py status

# Check policy violations
python opsec_cli.py violations --unresolved

# Monitor anonymity grid
python anonymity_cli.py stats
```

### Performance Metrics

- Query success/failure rates
- Response times and timeouts
- Policy enforcement statistics
- Anonymity mixing effectiveness

## 🔧 CLI Tools Reference

| Tool | Purpose | Key Commands |
|------|---------|--------------|
| `audit_cli.py` | Audit trail management | `log`, `verify`, `search`, `export` |
| `opsec_cli.py` | Policy enforcement | `list`, `test`, `violations`, `create` |
| `anonymity_cli.py` | Anonymity grid | `start`, `query`, `batch`, `stats` |
| `secrets_cli.py` | Secrets management | `store`, `get`, `list`, `delete` |
| `result_encryption_cli.py` | Result encryption | `encrypt`, `decrypt`, `list`, `burn` |

## 🎯 Use Cases

### Investigative Journalism

- Source protection through anonymity
- Evidence preservation with audit trails
- Secure storage of sensitive findings

### Corporate Security

- Threat intelligence gathering
- Brand monitoring and protection
- Incident response and forensics

### Academic Research

- Social media analysis
- Network topology research
- Disinformation studies

### Penetration Testing

- Reconnaissance phase operations
- Target profiling and analysis
- Infrastructure mapping

## 🤝 Integration

### Python API

```python
from osint_utils import OSINTUtils
from anonymity_grid import anonymous_query

# Standard secure operation
utils = OSINTUtils()
response = utils.make_request("https://example.com")

# Anonymous operation
result = anonymous_query("domain_lookup", "example.com")
```

### REST API

```bash
# Start REST API server
python restful_osint.py

# Submit requests via HTTP
curl -X POST http://localhost:5000/api/investigate \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "modules": ["domain", "email"]}'
```

## ⚠️ Legal & Ethical Guidelines

### Compliance

- Respect robots.txt and rate limits
- Follow local and international laws
- Obtain proper authorization for investigations

### Best Practices

- Use minimum necessary data collection
- Implement data retention policies
- Regular security audits and updates
- Staff training on OSINT ethics

## 📈 Performance

### Benchmarks

- **Tor Latency**: ~2-5x normal HTTP (acceptable for OSINT)
- **DoH Overhead**: ~50-100ms additional per DNS query
- **Encryption Impact**: <1% performance overhead
- **Mixing Delay**: 1-60 seconds based on priority

### Scalability

- Supports multiple concurrent operations
- Horizontal scaling via anonymity grid
- Configurable resource limits
- Automatic rate limiting

## 🔄 Updates & Maintenance

### Regular Tasks

```bash
# Update Tor circuits
python tor_control.py rotate_circuits

# Verify audit integrity
python audit_cli.py verify

# Clean expired results
python result_encryption_cli.py cleanup

# Update policy violations
python opsec_cli.py violations --resolve-old
```

### Monitoring Health

- Check Tor connectivity regularly
- Monitor disk space for logs/encrypted results
- Verify policy enforcement is active
- Test anonymity grid connectivity

## 🆘 Troubleshooting

### Common Troubleshooting Issues

**Tor Connection Failed**

```bash
# Check Tor service
sudo systemctl status tor

# Test SOCKS proxy
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

**DoH Resolution Errors**

```bash
# Test DoH resolver
python doh_client.py test

# Check resolver configuration
python -c "from doh_client import DoHClient; print(DoHClient().get_resolver_stats())"
```

**Policy Violations**

```bash
# Check policy status
python opsec_cli.py list

# Review recent violations
python opsec_cli.py violations --limit 10
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Tor Project** for anonymity infrastructure
- **Bellingcat** for investigative journalism inspiration
- **OSINT Community** for methodology and best practices
- **Security Researchers** for operational security guidance

## 📞 Support

For support, questions, or contributions:

- Open an issue on GitHub
- Review the documentation in `/docs`
- Check existing discussions and solutions

---

**⚠️ Disclaimer**: This tool is for legitimate OSINT activities only. Users are responsible for compliance with applicable laws and ethical guidelines. The authors assume no liability for misuse.

**🔒 Security Note**: Regularly update dependencies and review security configurations. This tool provides strong anonymity and security but is not bulletproof against all threats.
