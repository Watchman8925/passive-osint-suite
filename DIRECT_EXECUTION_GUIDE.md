# OSINT Suite - Direct Execution Guide
# Run the OSINT suite without Docker containers

## 🎯 Quick Start

### Option 1: Interactive OSINT Suite
```bash
./start_direct.sh --quiet
```
This launches the full interactive menu with all investigation tools.

### Option 2: Command Line Analysis
```bash
# Analyze a domain
./start_direct.sh --domain example.com

# Analyze an email
./start_direct.sh --email user@example.com

# Analyze an IP address
./start_direct.sh --ip 192.168.1.1

# Analyze a company
./start_direct.sh --company "Example Corp"
```

### Option 3: API Server
```bash
./start_api.sh
```
Starts the FastAPI server on http://localhost:8000 with full REST API and WebSocket support.

## 🔧 Prerequisites

- Python 3.12+
- Virtual environment with dependencies installed
- All required API keys configured (optional)

## 📋 Available Investigation Modules

The suite includes comprehensive OSINT capabilities:

### Core Analysis Tools
- 🕵️ **Domain Intelligence** - WHOIS, DNS, certificates
- 📧 **Email Intelligence** - Breach checks, social media correlation
- 🌐 **IP Intelligence** - Geolocation, reputation, routing
- 🏢 **Company Intelligence** - Business records, executive data
- ✈️ **Flight Intelligence** - Aircraft tracking and analysis
- ₿ **Crypto Intelligence** - Blockchain analysis and wallet tracking

### Advanced Analysis Suite
- 🎯 **Hidden Pattern Detection** - Advanced pattern analysis
- 🔍 **Conspiracy Theory Analysis** - Multi-source correlation
- 🔗 **Cross-Reference Engine** - Evidence linking and verification
- ⚫ **Blackbox Pattern Analysis** - Unconventional data analysis

### Intelligence & Reporting
- 📊 **Reporting Engine** - Automated report generation
- 📡 **Real-time Feeds** - Live intelligence monitoring
- 🕵️ **Bellingcat Toolkit** - Open source investigation methods

### Specialized Tools
- 🔬 **Digital Forensics** - File analysis and metadata extraction
- 🌍 **Geospatial Intelligence** - Location-based analysis
- 💰 **Financial Intelligence** - Economic data and trends
- 🔒 **Security Analysis** - Threat intelligence and risk assessment

## 🚀 Advanced Usage

### Environment Variables
```bash
export OSINT_USE_KEYRING=false    # Disable system keyring
export OSINT_TEST_MODE=false      # Production mode
export HOST=0.0.0.0              # API server host
export PORT=8000                 # API server port
```

### API Endpoints (when running API server)

#### Core Investigation
- `POST /api/investigate/domain/{domain}` - Domain analysis
- `POST /api/investigate/email/{email}` - Email analysis
- `POST /api/investigate/ip/{ip}` - IP analysis
- `POST /api/investigate/company/{company}` - Company analysis

#### Advanced Analysis
- `POST /api/analysis/patterns` - Pattern detection
- `POST /api/analysis/conspiracy` - Conspiracy analysis
- `POST /api/analysis/cross-reference` - Cross-referencing
- `POST /api/analysis/blackbox` - Blackbox analysis

#### Real-time Features
- `WebSocket /ws/investigation/{session_id}` - Real-time updates
- `GET /api/feeds/status` - Feed monitoring status
- `GET /api/alerts/active` - Active intelligence alerts

#### Reporting
- `POST /api/reports/generate` - Generate intelligence report
- `GET /api/reports/{report_id}` - Retrieve report
- `GET /api/reports/list` - List available reports

## 🔐 Security Features

- **Query Obfuscation** - Automatic request anonymization
- **Result Encryption** - Encrypted data storage
- **Audit Trails** - Complete activity logging
- **OPSEC Policies** - Operational security enforcement
- **API Key Management** - Secure credential storage

## 📊 Monitoring & Health

The suite includes built-in monitoring:
- Health checks via `/health`
- Metrics via `/metrics`
- Security monitoring and alerting
- Performance tracking and optimization

## 🐳 Docker vs Direct Execution

### When to use Docker:
- Production deployments
- Isolated environments
- Multi-service architectures
- CI/CD pipelines

### When to use Direct Execution:
- Development and testing
- Resource-constrained environments
- Quick analysis tasks
- Custom integrations

## 🆘 Troubleshooting

### Common Issues:

1. **Module Import Errors**
   ```bash
   # Ensure virtual environment is activated
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **API Key Issues**
   ```bash
   # Configure API keys in config/config.ini
   # Or use environment variables
   export SHODAN_API_KEY=your_key_here
   ```

3. **Permission Errors**
   ```bash
   # Ensure output directories exist and are writable
   mkdir -p output/encrypted output/audit output/logs logs policies
   ```

4. **Database Connection Issues**
   - The suite runs in mock mode without PostgreSQL
   - Full features require database setup (optional)

### Getting Help:
- Check logs in `logs/` directory
- Use `--verbose` flag for detailed output
- API documentation at `/docs` when running API server

## 🎉 Success!

Your OSINT suite is now running without Docker! All investigation modules are loaded and ready for use. The system provides comprehensive passive OSINT capabilities with advanced analysis tools, real-time monitoring, and professional reporting features.