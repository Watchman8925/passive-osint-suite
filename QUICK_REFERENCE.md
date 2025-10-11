# OSINT Suite - Quick Reference Card

## 🚀 Quick Start Commands

### Docker (Recommended)
```bash
# Start everything
docker-compose up -d

# Stop everything
docker-compose down

# View logs
docker-compose logs -f osint-api

# Restart service
docker-compose restart osint-api
```

### Local Development
```bash
# Start API
python api/api_server.py

# Start Web Interface
cd web && npm run dev

# Run Tests
pytest

# Run Linter
ruff check .
```

## 🌐 Access Points

- **Web Interface**: http://localhost:3000
- **API**: http://localhost:8000/api
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/api/health

## 📝 Common API Operations

### Authentication
```bash
# Get token (dev mode)
curl -X POST http://localhost:8000/api/dev/token

# Use token
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/api/investigations
```

### Investigations
```bash
# Create
curl -X POST http://localhost:8000/api/investigations \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","targets":["example.com"]}'

# List
curl http://localhost:8000/api/investigations

# Get details
curl http://localhost:8000/api/investigations/{id}

# Start
curl -X POST http://localhost:8000/api/investigations/{id}/start
```

### Execute Modules
```bash
# Domain recon
curl -X POST http://localhost:8000/api/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"module_name":"domain_recon","parameters":{"target":"example.com"}}'

# IP intel
curl -X POST http://localhost:8000/api/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"module_name":"ip_intel","parameters":{"target":"8.8.8.8"}}'

# Email search
curl -X POST http://localhost:8000/api/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"module_name":"breach_search","parameters":{"target":"user@example.com"}}'
```

## 🔧 Troubleshooting

### Docker Issues
```bash
# Check status
docker-compose ps

# View logs
docker-compose logs --tail=50 osint-api

# Restart all
docker-compose restart

# Clean rebuild
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### Database Issues
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U osint_user -d osint_audit

# Check tables
\dt

# View recent logs
SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10;
```

### Python Issues
```bash
# Install dependencies
pip install -r requirements.txt

# Check Python version
python --version  # Must be 3.10+

# Test imports
python -c "from modules import MODULE_REGISTRY; print('OK')"
```

### Tor Issues
```bash
# Start Tor
sudo systemctl start tor

# Check Tor status
curl --socks5 localhost:9050 https://check.torproject.org/api/ip

# Test in Python
python -c "from transport import sync_validate_tor_connection; print(sync_validate_tor_connection())"
```

## 📊 Module Quick Reference

### By Category

**Domain** (6 modules)
- `domain_recon` - Full domain analysis
- `dns_intelligence` - Advanced DNS
- `cert_transparency` - SSL certificates
- `passive_dns_enum` - Subdomains
- `whois_history` - WHOIS data
- `wayback` - Historical snapshots

**IP** (3 modules)
- `ip_intel` - IP analysis
- `network_analysis` - Network scan
- `iot_intel` - IoT devices

**Email** (2 modules)
- `email_intel` - Email analysis
- `breach_search` - Breach data

**Social** (4 modules)
- `social_footprint` - Multi-platform
- `social_passive` - Passive intel
- `github_search` - GitHub
- `gitlab_passive` - GitLab

**Dark Web** (5 modules)
- `darkweb_intel` - Dark web
- `breach_search` - Breaches
- `paste_monitor` - Pastebin
- `malware_intel` - Malware
- `threat_intel` - Threats

**Other**
- `crypto_intel` - Cryptocurrency
- `company_intel` - Companies
- `document_intel` - Documents
- `geospatial_intel` - Location
- `flight_intel` - Aviation
- `code_analysis` - Code security
- `pattern_matching` - Patterns

## 🔒 Security Commands

### Audit Trail
```bash
# View status
python scripts/audit_cli.py status

# Search operations
python scripts/audit_cli.py search --operation domain_lookup

# Verify integrity
python scripts/audit_cli.py verify
```

### OPSEC Policy
```bash
# Check policy
python scripts/demo_opsec.py

# View policies
cat policies/default_opsec.json
```

### Secrets Management
```bash
# Store secret
python -c "from security.secrets_manager import store_api_key; store_api_key('service', 'key')"

# List secrets
python -c "from security.secrets_manager import secrets_manager; print(secrets_manager.list_secrets())"
```

## 🐛 Debug Mode

### Enable Detailed Logging
```bash
# In .env
LOG_LEVEL=DEBUG
DEBUG=true

# Or environment variable
LOG_LEVEL=DEBUG python api/api_server.py
```

### Test Individual Module
```python
# In Python
from modules.domain_recon import DomainRecon

module = DomainRecon()
results = module.gather_intelligence("example.com")
print(results)
```

### Check Database
```bash
# Redis
docker-compose exec redis redis-cli ping

# PostgreSQL
docker-compose exec postgres pg_isready

# Elasticsearch
curl http://localhost:9200/_cluster/health
```

## 📦 Installation Issues

### Missing Dependencies
```bash
# System packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y python3-dev libffi-dev libssl-dev build-essential

# Python packages
pip install --upgrade pip
pip install -r requirements.txt

# Node packages
cd web && npm install
```

### Permission Issues
```bash
# Docker
sudo usermod -aG docker $USER
newgrp docker

# Files
sudo chown -R $USER:$USER .
chmod +x *.sh
```

## 🔑 Environment Variables

### Required
```bash
SECRET_KEY=your_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_here
POSTGRES_PASSWORD=your_db_password_here
GRAFANA_PASSWORD=your_grafana_password_here
```

### Optional but Recommended
```bash
SHODAN_API_KEY=your_shodan_key
GITHUB_API_TOKEN=your_github_token
VIRUSTOTAL_API_KEY=your_vt_key
OPENAI_API_KEY=your_openai_key
```

See `.env.example` for complete list.

## 🆘 Getting Help

1. **Check logs**: `docker-compose logs -f`
2. **Check documentation**: See README.md, USER_MANUAL.md
3. **Test API**: Visit http://localhost:8000/docs
4. **Run health check**: `curl http://localhost:8000/api/health/detailed`
5. **Open issue**: https://github.com/Watchman8925/passive-osint-suite/issues

## 💡 Tips & Tricks

### Performance
- Use Redis caching for repeated queries
- Limit concurrent requests in .env
- Use Docker for better resource isolation

### Security
- Always use Tor for sensitive operations
- Enable audit trail for compliance
- Use OPSEC policies to prevent mistakes
- Rotate API keys regularly

### Efficiency
- Create investigations for organized work
- Use batch operations for multiple targets
- Schedule reports for regular intelligence
- Export results for offline analysis

---

**Quick Help**: `docker-compose logs -f osint-api | grep ERROR`
