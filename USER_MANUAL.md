# Passive OSINT Suite - Complete User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [System Architecture](#system-architecture)
3. [Installation & Setup](#installation--setup)
4. [Using the Web Interface](#using-the-web-interface)
5. [Using the API](#using-the-api)
6. [OSINT Modules Reference](#osint-modules-reference)
7. [Security Features](#security-features)
8. [Investigation Workflows](#investigation-workflows)
9. [Docker Deployment](#docker-deployment)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Features](#advanced-features)

---

## Introduction

The Passive OSINT Suite is a comprehensive, production-ready Open Source Intelligence (OSINT) gathering platform designed for:

- **Intelligence Analysts** - Gather actionable intelligence from public sources
- **Security Researchers** - Investigate threats and vulnerabilities
- **Law Enforcement** - Conduct investigations with full audit trails
- **Corporate Security** - Monitor digital footprints and threats

### Key Features

✅ **38+ OSINT Modules** covering domains, IPs, emails, social media, dark web, and more  
✅ **Modern Web Interface** built with React and TypeScript  
✅ **RESTful API** for automation and integration  
✅ **Anonymous Operations** via Tor and DNS-over-HTTPS  
✅ **Cryptographic Audit Trail** with Ed25519 signatures  
✅ **Investigation Management** with task tracking and provenance  
✅ **AI-Powered Analysis** with local LLM support  
✅ **Docker Deployment** for easy scaling  
✅ **OPSEC Policies** to prevent operational security violations  
✅ **Rate Limiting** and security hardening throughout  

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Interface (React)                     │
│                     http://localhost:3000                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ HTTP/WebSocket
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                  API Server (FastAPI)                        │
│                  http://localhost:8000/api                   │
├──────────────────────────────────────────────────────────────┤
│  • Authentication (JWT)     • Rate Limiting                  │
│  • Investigation Manager    • OPSEC Policy Engine            │
│  • Module Executor          • Audit Trail                    │
│  • Real-time Feeds          • Graph Database                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
┌─────────▼────────┐ ┌─────▼──────┐ ┌─────▼──────────┐
│   PostgreSQL     │ │   Redis    │ │  Elasticsearch │
│   (Audit Logs)   │ │  (Cache)   │ │    (Search)    │
└──────────────────┘ └────────────┘ └────────────────┘
```

### Components

1. **Web Interface** - Modern React-based UI for investigations
2. **API Server** - FastAPI backend with WebSocket support
3. **OSINT Modules** - 38+ specialized intelligence gathering modules
4. **Security Layer** - RBAC, rate limiting, OPSEC policies, audit trail
5. **Data Stores** - PostgreSQL (audit), Redis (cache), Elasticsearch (search)
6. **Anonymity Grid** - Tor integration and DNS-over-HTTPS

---

## Installation & Setup

### Prerequisites

- **Python 3.10+**
- **Node.js 16+** (for web interface)
- **Docker & Docker Compose** (for containerized deployment)
- **PostgreSQL** (optional, for audit logs)
- **Redis** (optional, for caching)

### Quick Start (5 minutes)

```bash
# 1. Clone the repository
git clone https://github.com/Watchman8925/passive-osint-suite.git
cd passive-osint-suite

# 2. Run automated setup
./setup.sh

# 3. Configure environment variables
cp .env.example .env
# Edit .env with your API keys and secrets

# 4. Start the API server
python api/api_server.py

# 5. Start the web interface (in another terminal)
cd web
npm install
npm run dev
```

Access the web interface at: http://localhost:3000

### Docker Deployment

```bash
# 1. Copy environment file
cp .env.example .env

# 2. Edit .env with your configuration
nano .env  # Set POSTGRES_PASSWORD and other secrets

# 3. Build and start containers
docker-compose up -d

# 4. Check status
docker-compose ps

# 5. View logs
docker-compose logs -f osint-api
```

Access via:
- Web Interface: http://localhost:3000
- API: http://localhost:8000/api
- API Docs: http://localhost:8000/docs

---

## Using the Web Interface

### Dashboard Overview

The main dashboard provides:

1. **Investigation List** - View and manage all investigations
2. **Quick Actions** - Create new investigations, run modules
3. **Real-time Alerts** - Intelligence feed notifications
4. **System Status** - Health checks and service status

### Creating an Investigation

1. Click **"New Investigation"** button
2. Fill in investigation details:
   - **Name**: Descriptive name (e.g., "Target Company Analysis")
   - **Type**: Select investigation type
   - **Targets**: Add domains, IPs, emails, etc.
   - **Priority**: High/Medium/Low
3. Click **"Create Investigation"**
4. Add tasks from the module catalog
5. Click **"Start Investigation"** to begin

### Running OSINT Modules

#### Method 1: Through Investigation
1. Open an investigation
2. Click **"Add Task"**
3. Select module from catalog
4. Configure module parameters
5. Click **"Run Task"**

#### Method 2: Direct Execution
1. Navigate to **"Modules"** page
2. Select a module
3. Enter target information
4. Click **"Execute"**
5. View results in real-time

### Viewing Results

Results are displayed in multiple formats:

- **Table View** - Structured data with sorting/filtering
- **Graph View** - Entity relationships and connections
- **Timeline View** - Temporal analysis of events
- **Export Options** - JSON, CSV, PDF reports

---

## Using the API

### Authentication

Get a JWT token:

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}'
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer"
}
```

Use the token in subsequent requests:
```bash
curl http://localhost:8000/api/investigations \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

### Key API Endpoints

#### Health Check
```bash
GET /api/health
GET /api/health/detailed
```

#### Investigations
```bash
# Create investigation
POST /api/investigations
{
  "name": "Target Analysis",
  "description": "Comprehensive OSINT on target",
  "targets": ["example.com", "192.168.1.1"],
  "investigation_type": "comprehensive",
  "priority": "high"
}

# List investigations
GET /api/investigations

# Get investigation details
GET /api/investigations/{id}

# Start investigation
POST /api/investigations/{id}/start

# Get tasks
GET /api/investigations/{id}/tasks
```

#### Modules
```bash
# List all modules
GET /api/modules

# Get module categories
GET /api/modules/categories

# Execute module
POST /api/modules/execute
{
  "module_name": "domain_recon",
  "parameters": {
    "target": "example.com"
  }
}
```

#### Reports
```bash
# Generate report
POST /api/reports/generate
{
  "investigation_id": "inv_123",
  "format": "pdf",
  "include_graphs": true
}

# Download report
GET /api/reports/download/{filename}

# Schedule report
POST /api/reports/schedule
{
  "investigation_id": "inv_123",
  "frequency": "daily",
  "format": "pdf"
}
```

### WebSocket Real-time Updates

Connect to WebSocket for real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/investigations/inv_123');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
};
```

---

## OSINT Modules Reference

### Domain Intelligence (6 modules)

#### 1. Domain Recon
Comprehensive domain reconnaissance including DNS, WHOIS, subdomains.
```python
# CLI
osint-suite domain-recon example.com

# API
POST /api/modules/execute
{"module_name": "domain_recon", "parameters": {"target": "example.com"}}
```

#### 2. DNS Intelligence
Advanced DNS queries, zone transfers, historical DNS.
```python
osint-suite dns-intelligence example.com
```

#### 3. Certificate Transparency
SSL/TLS certificate discovery and analysis.
```python
osint-suite cert-transparency example.com
```

#### 4. Subdomain Enumeration
Passive subdomain discovery via multiple sources.
```python
osint-suite passive-dns-enum example.com
```

#### 5. WHOIS History
Historical WHOIS data and ownership changes.
```python
osint-suite whois-history example.com
```

#### 6. Wayback Machine
Historical website snapshots and changes.
```python
osint-suite wayback example.com
```

### IP Intelligence (3 modules)

#### 1. IP Intelligence
Geolocation, ASN, hosting provider, reputation.
```python
osint-suite ip-intel 8.8.8.8
```

#### 2. Network Analysis
Network mapping, port scanning, service detection.
```python
osint-suite network-analysis 192.168.1.0/24
```

#### 3. IoT Intelligence
IoT device discovery and vulnerability assessment.
```python
osint-suite iot-intel 192.168.1.1
```

### Email Intelligence (2 modules)

#### 1. Email Intelligence
Email validation, breach checks, social profiles.
```python
osint-suite email-intel user@example.com
```

#### 2. Hunter.io Integration
Find email addresses associated with domains.
```python
osint-suite email-hunter example.com
```

### Social Media (4 modules)

#### 1. Social Media Footprint
Comprehensive social media profile discovery.
```python
osint-suite social-footprint username
```

#### 2. Comprehensive Social Passive
Multi-platform passive social media intelligence.
```python
osint-suite social-passive username
```

#### 3. GitHub Search
Code repositories, commits, and user activity.
```python
osint-suite github-search username
```

#### 4. GitLab/Bitbucket Passive
Alternative code hosting platforms.
```python
osint-suite gitlab-passive username
```

### Dark Web & Breaches (5 modules)

#### 1. Dark Web Intelligence
Dark web mentions and marketplace monitoring.
```python
osint-suite darkweb-intel target@example.com
```

#### 2. Public Breach Search
Data breach exposure across multiple databases.
```python
osint-suite breach-search user@example.com
```

#### 3. Paste Site Monitor
Pastebin and paste site monitoring.
```python
osint-suite paste-monitor email@example.com
```

#### 4. Malware Intelligence
Malware samples, hashes, and threat intelligence.
```python
osint-suite malware-intel abc123hash
```

#### 5. Threat Intelligence
Comprehensive threat actor and IOC intelligence.
```python
osint-suite threat-intel 192.168.1.1
```

### Cryptocurrency (1 module)

#### Cryptocurrency Intelligence
Blockchain analysis, wallet tracking, transaction history.
```python
osint-suite crypto-intel 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

### Company Intelligence (3 modules)

#### 1. Company Intelligence
Corporate records, financials, executives.
```python
osint-suite company-intel "Acme Corp"
```

#### 2. Financial Intelligence
Stock analysis, SEC filings, financial data.
```python
osint-suite financial-intel AAPL
```

#### 3. Patent Search
Patent filings and intellectual property.
```python
osint-suite patent-search "artificial intelligence"
```

### Media & Documents (4 modules)

#### 1. Document Intelligence
Document metadata extraction and analysis.
```python
osint-suite document-intel document.pdf
```

#### 2. Digital Forensics
File analysis, EXIF data, forensic artifacts.
```python
osint-suite digital-forensics image.jpg
```

#### 3. Web Discovery
Website technology stack, frameworks, libraries.
```python
osint-suite web-discovery example.com
```

#### 4. Web Scraper
Custom web scraping and data extraction.
```python
osint-suite web-scraper https://example.com
```

### Geospatial (2 modules)

#### 1. Geospatial Intelligence
Location analysis, mapping, coordinate conversion.
```python
osint-suite geospatial-intel 40.7128,-74.0060
```

#### 2. Flight Intelligence
Aircraft tracking, flight history, aviation data.
```python
osint-suite flight-intel N12345
```

### Academic & Research (1 module)

#### Academic Intelligence
Research papers, citations, author profiles.
```python
osint-suite academic-passive "John Smith"
```

### Analysis & Pattern Matching (4 modules)

#### 1. Code Analysis
Source code security analysis and vulnerability detection.
```python
osint-suite code-analysis /path/to/code
```

#### 2. Pattern Matching
Custom pattern detection across datasets.
```python
osint-suite pattern-matching "regex_pattern"
```

#### 3. Hidden Pattern Detector
Advanced pattern recognition and anomaly detection.
```python
osint-suite hidden-patterns dataset.json
```

#### 4. Conspiracy Analyzer
Link analysis and relationship mapping.
```python
osint-suite conspiracy-analyzer entities.json
```

---

## Security Features

### 1. Cryptographic Audit Trail

Every operation is logged with Ed25519 signatures:

```python
# View audit logs
python scripts/audit_cli.py status

# Search operations
python scripts/audit_cli.py search --operation domain_lookup --actor user123

# Verify integrity
python scripts/audit_cli.py verify
```

### 2. OPSEC Policy Engine

Prevents operational security violations:

```python
from security.opsec_policy import enforce_policy

# Check if operation is allowed
result = enforce_policy(
    operation_type="scan",
    target="192.168.1.1",
    actor="analyst"
)

if not result["allowed"]:
    print(f"Blocked: {result['reason']}")
```

### 3. Rate Limiting

API endpoints are rate-limited to prevent abuse:

```python
# Health endpoint: 300 requests/minute
# Investigation creation: 15 requests/minute
# Module execution: 30 requests/minute
```

### 4. Anonymous Operations

All network requests go through Tor:

```python
# Check Tor status
GET /tor/status

# Validate Tor connection
from transport import sync_validate_tor_connection
is_connected = sync_validate_tor_connection()
```

### 5. Result Encryption

Sensitive results are encrypted with AES-256-GCM:

```python
from security.result_encryption import result_encryption

# Encrypt result
encrypted_id = result_encryption.encrypt_result(
    data={"sensitive": "information"},
    expiry_hours=24
)

# Retrieve result
result = result_encryption.get_result(encrypted_id)
```

---

## Investigation Workflows

### Workflow 1: Domain Investigation

```bash
# 1. Create investigation
curl -X POST http://localhost:8000/api/investigations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example.com Investigation",
    "targets": ["example.com"],
    "investigation_type": "domain"
  }'

# 2. Get investigation ID from response
INV_ID="inv_abc123"

# 3. Add domain recon task
curl -X POST http://localhost:8000/api/investigations/$INV_ID/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"module": "domain_recon", "target": "example.com"}'

# 4. Add subdomain enumeration
curl -X POST http://localhost:8000/api/investigations/$INV_ID/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"module": "passive_dns_enum", "target": "example.com"}'

# 5. Start investigation
curl -X POST http://localhost:8000/api/investigations/$INV_ID/start \
  -H "Authorization: Bearer $TOKEN"

# 6. Monitor progress
curl http://localhost:8000/api/investigations/$INV_ID/progress \
  -H "Authorization: Bearer $TOKEN"

# 7. Generate report
curl -X POST http://localhost:8000/api/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"investigation_id": "'$INV_ID'", "format": "pdf"}'
```

### Workflow 2: Email Investigation

```bash
# 1. Search for breaches
osint-suite breach-search target@example.com

# 2. Find social media profiles
osint-suite social-footprint target

# 3. Check email validation
osint-suite email-intel target@example.com

# 4. Search paste sites
osint-suite paste-monitor target@example.com
```

### Workflow 3: IP Investigation

```bash
# 1. Get IP intelligence
osint-suite ip-intel 192.168.1.1

# 2. Network analysis
osint-suite network-analysis 192.168.1.0/24

# 3. Threat intelligence
osint-suite threat-intel 192.168.1.1

# 4. Historical data
osint-suite ip-history 192.168.1.1
```

---

## Docker Deployment

### Production Deployment

```yaml
# docker-compose.yml highlights
services:
  osint-api:
    image: osint-suite:latest
    environment:
      - ENVIRONMENT=production
      - SECRET_KEY=${SECRET_KEY}
    ports:
      - "8000:8000"
    
  osint-web:
    image: osint-web:latest
    ports:
      - "3000:80"
    
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

### Scaling

```bash
# Scale API workers
docker-compose up -d --scale osint-api=3

# Add load balancer (nginx)
docker-compose -f docker-compose.yml -f docker-compose.lb.yml up -d
```

### Monitoring

```bash
# View logs
docker-compose logs -f osint-api

# Check health
curl http://localhost:8000/api/health/detailed

# Monitor resources
docker stats
```

---

## Troubleshooting

### Common Issues

#### 1. Module Import Errors

**Problem**: ModuleNotFoundError when running modules

**Solution**:
```bash
# Install missing dependencies
pip install -r requirements.txt

# Or install specific package
pip install dnspython
```

#### 2. Tor Connection Failed

**Problem**: "Tor proxy is not accessible"

**Solution**:
```bash
# Start Tor service
sudo systemctl start tor

# Or install Tor
sudo apt install tor

# Check Tor status
curl --socks5 localhost:9050 https://check.torproject.org
```

#### 3. Database Connection Error

**Problem**: "Failed to connect to PostgreSQL"

**Solution**:
```bash
# Check .env file has correct password
grep POSTGRES_PASSWORD .env

# Start PostgreSQL container
docker-compose up -d postgres

# Verify connection
docker-compose exec postgres psql -U osint_user -d osint_audit
```

#### 4. Frontend Build Issues

**Problem**: npm build fails

**Solution**:
```bash
cd web
rm -rf node_modules package-lock.json
npm install
npm run build
```

#### 5. Rate Limit Exceeded

**Problem**: "Rate limit exceeded" error

**Solution**:
```bash
# Wait for rate limit window to reset
# Or adjust limits in .env
API_RATE_LIMIT=2000/hour
```

---

## Advanced Features

### 1. Custom Module Development

Create your own OSINT module:

```python
# modules/my_module.py
from utils.osint_utils import OSINTUtils

class MyCustomModule(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Module"
    
    def gather_intelligence(self, target):
        """Main intelligence gathering method"""
        results = {
            "target": target,
            "data": []
        }
        
        # Your custom logic here
        
        return results
```

Register in `modules/__init__.py`:
```python
from .my_module import MyCustomModule

MODULE_REGISTRY["my_module"] = {
    "class": MyCustomModule,
    "name": "My Custom Module",
    "category": "custom"
}
```

### 2. AI-Powered Analysis

Use local LLM for intelligence analysis:

```python
from core.local_llm_engine import LocalLLMEngine

engine = LocalLLMEngine()

# Analyze investigation
analysis = await engine.analyze_investigation(
    investigation_data,
    focus_areas=["threats", "connections"]
)

print(analysis.insights)
print(analysis.risk_assessment)
```

### 3. Graph Database Integration

Store and query entity relationships:

```python
from database.graph_database import GraphDatabaseAdapter

graph = GraphDatabaseAdapter()

# Add entities
graph.add_entity("domain", "example.com", {"ip": "1.2.3.4"})
graph.add_entity("ip", "1.2.3.4", {"asn": "AS1234"})

# Add relationship
graph.add_relationship("example.com", "1.2.3.4", "resolves_to")

# Query relationships
related = graph.get_related_entities("example.com")
```

### 4. Real-time Intelligence Feeds

Subscribe to real-time threat intelligence:

```python
from realtime.realtime_feeds import RealTimeIntelligenceFeed

feeds = RealTimeIntelligenceFeed()

# Subscribe to alerts
subscription_id = await feeds.subscribe_to_alerts(
    user_id="user123",
    alert_types=["malware", "breach"],
    channels=["websocket", "email"]
)
```

### 5. Scheduled Reports

Automate report generation:

```python
from reporting.report_scheduler import ReportScheduler

scheduler = ReportScheduler()

# Schedule daily report
schedule_id = scheduler.schedule_report(
    investigation_id="inv_123",
    frequency="daily",
    format="pdf",
    recipients=["analyst@example.com"]
)
```

---

## Support & Contributing

### Getting Help

- **Documentation**: See all MD files in repository
- **Issues**: https://github.com/Watchman8925/passive-osint-suite/issues
- **Discussions**: GitHub Discussions tab

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -am 'Add my feature'`
4. Push to branch: `git push origin feature/my-feature`
5. Submit a Pull Request

### License

See [LICENSE.md](LICENSE.md) for details.

---

**Version**: 2.0.0  
**Last Updated**: October 2025  
**Status**: Production Ready ✅
