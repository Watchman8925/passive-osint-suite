# Docker Deployment Guide

Complete guide for deploying the Passive OSINT Suite using Docker and Docker Compose.

## 🚀 Quick Start

### Prerequisites
- Docker 20.10+ and Docker Compose v2.0+
- At least 8GB RAM (16GB recommended)
- 20GB free disk space (for models and data)

### One-Command Deployment

```bash
# 1. Clone and setup
git clone https://github.com/Watchman8925/passive-osint-suite.git
cd passive-osint-suite

# 2. Configure environment
cp .env.example .env
# Edit .env with your API keys and settings

# 3. Deploy everything
docker-compose up -d
```

## 📋 Step-by-Step Deployment

### 1. Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Generate secure keys
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"

# Edit .env file with your settings
nano .env
```

**Critical Environment Variables:**
```bash
# Security (REQUIRED)
SECRET_KEY=your_generated_secret_key_here
OSINT_MASTER_KEY=your_secure_master_key_here
POSTGRES_PASSWORD=your_secure_database_password

# Optional but recommended API keys
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
GITHUB_API_TOKEN=your_github_token
```

### 2. Build and Deploy

```bash
# Build all services
docker-compose build

# Start all services in background
docker-compose up -d

# Watch logs
docker-compose logs -f osint-suite
```

### 3. Verify Deployment

```bash
# Check service status
docker-compose ps

# Check analysis modules
docker exec osint-suite python -c "
from modules import MODULE_REGISTRY
print(f'Total modules: {len(MODULE_REGISTRY)}')
analysis_modules = ['bellingcat_toolkit', 'blackbox_patterns', 'conspiracy_analyzer', 'cross_reference_engine', 'hidden_pattern_detector']
found = [m for m in analysis_modules if m in MODULE_REGISTRY]
print(f'Analysis modules: {len(found)}/5 working')
"

# Test API endpoint
curl http://localhost:8000/health
```

## 🔧 Service Architecture

The Docker deployment includes:

- **osint-suite** (Port 8000): Main OSINT application with 48+ modules
- **tor-proxy** (Ports 9050/9051): Tor proxy for anonymization
- **postgres** (Port 5432): Database for audit trails
- **redis** (Port 6379): Caching and session management
- **prometheus** (Port 9090): Metrics collection
- **grafana** (Port 3000): Monitoring dashboard
- **loki** (Port 3100): Log aggregation

## 🌐 Access Points

After deployment, access these services:

- **Main API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Grafana Dashboard**: http://localhost:3000 (admin/admin123)
- **Prometheus Metrics**: http://localhost:9090
- **Health Check**: http://localhost:8000/health

## 📦 Volume Management

Important data directories:
```bash
# Application data
./output:/app/output          # Analysis results
./logs:/app/logs              # Application logs
./policies:/app/policies      # Security policies

# Database data (Docker volumes)
postgres_data                 # PostgreSQL data
redis_data                    # Redis cache
grafana_data                  # Grafana dashboards
prometheus_data               # Metrics data
loki_data                     # Log data
```

## 🔍 Usage Examples

### CLI Usage (Docker)
```bash
# Run domain analysis
docker exec osint-suite python main.py --target example.com --modules whois,dns,ssl

# Extract metadata from files
docker exec osint-suite python main.py --extract-metadata --file /app/output/document.pdf

# Run security audit
docker exec osint-suite python scripts/security_audit.py

# Access interactive shell
docker exec -it osint-suite bash
```

### API Usage
```bash
# Health check
curl http://localhost:8000/health

# List all modules
curl http://localhost:8000/modules

# Start analysis
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "modules": ["whois", "dns", "ssl"]}'

# Get analysis results
curl http://localhost:8000/results/{analysis_id}
```

### Python API Usage
```python
import requests

# API base URL
api_url = "http://localhost:8000"

# Start Bellingcat analysis
response = requests.post(f"{api_url}/analyze", json={
    "target": "suspicious-domain.com",
    "modules": ["bellingcat_toolkit", "blackbox_patterns", "conspiracy_analyzer"]
})

# Get results
analysis_id = response.json()["analysis_id"]
results = requests.get(f"{api_url}/results/{analysis_id}").json()
```

## 🔧 Troubleshooting

### Common Issues

1. **Container fails to start**
   ```bash
   # Check logs
   docker-compose logs osint-suite
   
   # Check resource usage
   docker stats
   ```

2. **Missing analysis modules**
   ```bash
   # Rebuild with no cache
   docker-compose build --no-cache osint-suite
   docker-compose up -d osint-suite
   ```

3. **Model download issues**
   ```bash
   # Models download at runtime - check logs
   docker-compose logs osint-suite | grep -i "model"
   
   # Clear cache and restart
   docker-compose down
   docker volume rm $(docker volume ls -q | grep osint)
   docker-compose up -d
   ```

4. **Permission issues**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER ./output ./logs ./policies
   ```

### Performance Tuning

1. **Memory optimization**
   ```yaml
   # In docker-compose.yml, add memory limits
   services:
     osint-suite:
       mem_limit: 8g
       mem_reservation: 4g
   ```

2. **CPU optimization**
   ```yaml
   # Limit CPU usage
   services:
     osint-suite:
       cpus: '4.0'
   ```

## 📊 Monitoring

### Grafana Dashboard
1. Access http://localhost:3000
2. Login: admin/admin123 (change password!)
3. Import OSINT Suite dashboard
4. Monitor system metrics, analysis performance

### Prometheus Metrics
- System resources: CPU, memory, disk
- Application metrics: analysis count, module usage
- Security metrics: failed attempts, anomalies

### Log Analysis
```bash
# View application logs
docker-compose logs -f osint-suite

# Search logs
docker-compose logs osint-suite | grep -i "error"

# Export logs
docker-compose logs --no-color osint-suite > osint-logs.txt
```

## 🔒 Security Hardening

### Production Deployment
1. **Change default passwords**
   ```bash
   # Update .env file
   POSTGRES_PASSWORD=very_secure_database_password
   GRAFANA_ADMIN_PASSWORD=very_secure_grafana_password
   OSINT_MASTER_KEY=very_secure_master_key
   ```

2. **Use HTTPS reverse proxy**
   ```yaml
   # Add nginx proxy
   nginx:
     image: nginx:alpine
     ports:
       - "443:443"
       - "80:80"
     volumes:
       - ./nginx.conf:/etc/nginx/nginx.conf
       - ./ssl:/etc/nginx/ssl
   ```

3. **Network isolation**
   ```yaml
   # Create isolated networks
   networks:
     frontend:
       driver: bridge
     backend:
       driver: bridge
       internal: true
   ```

### Backup Strategy
```bash
# Database backup
docker exec osint-postgres pg_dump -U osint_user osint_audit > backup.sql

# Volume backup
docker run --rm -v osint_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz /data

# Application data backup
tar czf osint_data_backup.tar.gz output/ logs/ policies/
```

### Hardened Runtime Flags (Recommended)

For single-container runs, apply restrictive flags at runtime:

```bash
docker run -d \
   --name osint-suite \
   --read-only \
   --cap-drop ALL \
   --security-opt no-new-privileges \
   --pids-limit 256 \
   --memory 2g --memory-swap 2g \
   -v osint-data:/app/output \
   -p 8000:8000 \
   watchman89/passive-osint-suite:latest
```

Notes:
- The container runs as a non-root user by default.
- Mount `/app/output` as a volume to allow writes with a read-only rootfs.
- Adjust memory and PID limits to your environment.

### Compose Production Override (Example)

Create `docker-compose.override.yml` with hardening options:

```yaml
services:
   osint-suite:
      read_only: true
      cap_drop: ["ALL"]
      security_opt:
         - no-new-privileges:true
      deploy:
         resources:
            limits:
               cpus: '4.0'
               memory: 8g
            reservations:
               memory: 4g
      volumes:
         - osint-data:/app/output

volumes:
   osint-data:
```

Then run `docker-compose up -d` to apply overrides.

## 🔄 Updates and Maintenance

### Update Application
```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose build --no-cache osint-suite
docker-compose up -d osint-suite
```

### Clean Up
```bash
# Remove old containers and images
docker system prune -f

# Remove unused volumes (CAUTION: This deletes data!)
docker volume prune -f

# Clean logs
docker-compose exec osint-suite find /app/logs -name "*.log" -mtime +30 -delete
```

## 📞 Support

- **Documentation**: Full docs at `/docs` directory
- **API Reference**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Logs**: `docker-compose logs osint-suite`

For issues:
1. Check logs first: `docker-compose logs osint-suite`
2. Verify all 48 modules loaded
3. Check disk space and memory usage
4. Review environment variables in `.env`

## ✅ Docker Compliance and Security Automation

This project includes guardrails to help you maintain container best practices and security:

- Dockerfile linting: Hadolint runs on every push/PR to flag issues. See `.github/workflows/docker-lint.yml` and `.hadolint.yaml`.
- Image vulnerability scanning: Trivy scans HIGH/CRITICAL and uploads SARIF to your repo’s Security tab.
- Image best-practice lint: Dockle audits the built image and fails on critical findings.
- Supply chain: CI builds multi-arch images with SBOM and SLSA provenance and signs all tags using Cosign keyless; CI also verifies signatures.
- Hardened runtime: Use `docker-compose.override.hardened.yml` to enforce read-only rootfs, drop all capabilities, enable no-new-privileges, tmpfs for /tmp, and resource limits.

**Enhanced Security Features:**
- Pinned base image digest for reproducibility
- Automated Trivy scanning workflow (`.github/workflows/trivy-scan.yml`)
- Comprehensive security scanning script (`scripts/scan_docker_image.sh`)

For detailed security documentation, see **[DOCKER_SECURITY.md](DOCKER_SECURITY.md)**.

Local tips (optional):

- Run comprehensive security scan:
   ./scripts/scan_docker_image.sh local/osint-suite:dev

- Apply hardening with Compose override:
   docker compose -f docker-compose.yml -f docker-compose.override.hardened.yml up -d

- Run Hadolint locally:
   docker run --rm -i hadolint/hadolint < Dockerfile

- Run Trivy locally:
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     aquasec/trivy:latest image --severity HIGH,CRITICAL local/osint-suite:dev

- Run Dockle locally after a build:
   docker build -t local/osint-suite:dev .
   docker run --rm goodwithtech/dockle:v0.4.13 local/osint-suite:dev
