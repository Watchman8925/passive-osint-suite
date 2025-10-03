# OSINT Suite - Setup & Deployment Guide

## 🚀 Quick Start (Development)

### Prerequisites

- Python 3.10+
- Node.js 18+
- Docker & Docker Compose
- Git

### 1. Clone the Repository

```bash
git clone <repository-url>
cd osint-suite
```

### 2. Generate Secure Secret Key

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Save this output - you'll need it for the `.env` file.

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set **required** values:

```bash
# CRITICAL: Set this to your generated secret key
OSINT_SECRET_KEY=<your-generated-secret-key>

# Environment
ENVIRONMENT=development

# Database passwords (for Docker)
POSTGRES_PASSWORD=<secure-password>
GRAFANA_PASSWORD=<secure-password>

# Enable dev auth (development only!)
ENABLE_DEV_AUTH=1
```

### 4. Install Python Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 5. Install Frontend Dependencies

```bash
cd web
npm install
cd ..
```

### 6. Start Services with Docker

```bash
# Start supporting services (Tor, Redis, PostgreSQL, Monitoring)
docker-compose up -d

# Wait for services to be ready
sleep 10
```

### 7. Start Backend API

```bash
source venv/bin/activate
python api/api_server.py
```

The API will be available at `http://localhost:8000`

### 8. Start Frontend (in a new terminal)

```bash
cd web
npm run dev
```

The frontend will be available at `http://localhost:3000`

### 9. Verify Installation

```bash
# Check API health
curl http://localhost:8000/api/health

# Check detailed health
curl http://localhost:8000/api/health/detailed
```

---

## 🏭 Production Deployment

### Pre-Deployment Checklist

- [ ] All secrets generated and securely stored
- [ ] Environment variables configured
- [ ] Database backups configured
- [ ] SSL/TLS certificates obtained
- [ ] Firewall rules configured
- [ ] Monitoring and alerting setup
- [ ] Backup and recovery procedures documented

### 1. Environment Configuration

Create production `.env`:

```bash
# =============================================================================
# CRITICAL SECURITY SETTINGS (PRODUCTION)
# =============================================================================
OSINT_SECRET_KEY=<use-secrets-manager-in-production>
ENVIRONMENT=production
ENABLE_DEV_AUTH=0  # NEVER enable in production

# CORS (use your actual production domains)
CORS_ORIGINS=https://osint.yourdomain.com,https://api.yourdomain.com

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
DATABASE_URL=postgresql://osint_user:secure_password@db.internal/osint_db
REDIS_URL=redis://:password@redis.internal:6379
ELASTICSEARCH_URL=https://es.internal:9200

# PostgreSQL
POSTGRES_USER=osint_user
POSTGRES_PASSWORD=<use-secrets-manager>
POSTGRES_DB=osint_audit

# =============================================================================
# MONITORING
# =============================================================================
GRAFANA_ADMIN_USER=admin
GRAFANA_PASSWORD=<use-secrets-manager>

# =============================================================================
# API KEYS (Optional - as needed)
# =============================================================================
SHODAN_API_KEY=<your-key>
VIRUSTOTAL_API_KEY=<your-key>
OPENAI_API_KEY=<your-key>
# ... add others as needed
```

### 2. Build Frontend for Production

```bash
cd web
npm run build
```

This creates optimized production files in `web/dist/`

### 3. Deploy with Docker

#### Option A: Docker Compose (Recommended for small deployments)

```bash
# Build images
docker-compose build

# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f osint-suite
```

#### Option B: Kubernetes (Recommended for large deployments)

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: osint-suite
spec:
  replicas: 3
  selector:
    matchLabels:
      app: osint-suite
  template:
    metadata:
      labels:
        app: osint-suite
    spec:
      containers:
      - name: osint-suite
        image: osint-suite:latest
        env:
        - name: OSINT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: osint-secrets
              key: secret-key
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health/detailed
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### 4. Configure Reverse Proxy (nginx)

```nginx
# /etc/nginx/sites-available/osint-suite
server {
    listen 443 ssl http2;
    server_name osint.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/osint.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/osint.yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Frontend
    location / {
        root /var/www/osint-suite/dist;
        try_files $uri $uri/ /index.html;
    }

    # API
    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting
        limit_req zone=api burst=20 nodelay;
    }

    # WebSocket support
    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name osint.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

Enable and restart nginx:

```bash
sudo ln -s /etc/nginx/sites-available/osint-suite /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 5. Configure Monitoring

Access Grafana at `http://localhost:3000` (or your production domain)

Default credentials:
- Username: admin
- Password: (set in `.env`)

**Change password immediately after first login!**

Import dashboards from `docker/grafana-dashboards/`

### 6. Set Up Backups

```bash
#!/bin/bash
# backup.sh - Daily backup script

BACKUP_DIR=/backups/osint-suite
DATE=$(date +%Y%m%d_%H%M%S)

# Backup PostgreSQL
docker exec osint-postgres pg_dump -U osint_user osint_audit | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Backup investigation data
tar -czf $BACKUP_DIR/investigations_$DATE.tar.gz investigation_store/

# Backup Redis (if needed)
docker exec osint-redis redis-cli SAVE
docker cp osint-redis:/data/dump.rdb $BACKUP_DIR/redis_$DATE.rdb

# Keep only last 30 days
find $BACKUP_DIR -mtime +30 -delete

echo "Backup completed: $DATE"
```

Add to crontab:

```bash
# Daily backup at 2 AM
0 2 * * * /path/to/backup.sh >> /var/log/osint-backup.log 2>&1
```

---

## 🔒 Security Hardening

### 1. Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

### 2. SSL/TLS Configuration

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d osint.yourdomain.com

# Auto-renewal
sudo certbot renew --dry-run
```

### 3. Database Security

```sql
-- PostgreSQL hardening
-- Run as superuser

-- Create dedicated user
CREATE USER osint_user WITH ENCRYPTED PASSWORD 'secure_password';

-- Create database
CREATE DATABASE osint_audit OWNER osint_user;

-- Revoke public access
REVOKE ALL ON DATABASE osint_audit FROM PUBLIC;

-- Grant only necessary permissions
GRANT CONNECT ON DATABASE osint_audit TO osint_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO osint_user;

-- Enable SSL
-- Edit postgresql.conf:
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
```

### 4. API Rate Limiting (nginx)

Add to nginx configuration:

```nginx
http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;

    # Connection limits
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    server {
        # Apply rate limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            limit_conn conn_limit 10;
        }

        location /api/auth/ {
            limit_req zone=auth burst=5 nodelay;
        }
    }
}
```

### 5. Log Management

```bash
# Configure log rotation
# /etc/logrotate.d/osint-suite

/var/log/osint-suite/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        docker-compose restart osint-suite
    endscript
}
```

---

## 📊 Monitoring & Alerting

### Key Metrics to Monitor

1. **Application Metrics**
   - Request rate
   - Error rate
   - Response time (p50, p95, p99)
   - Active investigations

2. **System Metrics**
   - CPU usage
   - Memory usage
   - Disk I/O
   - Network traffic

3. **Security Metrics**
   - Failed authentication attempts
   - Rate limit violations
   - Unusual access patterns
   - API key usage

### Alert Configuration

Create alerts in Grafana or Prometheus:

```yaml
# prometheus/alerts.yml
groups:
  - name: osint_suite
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected"

      - alert: ServiceDown
        expr: up{job="osint-suite"} == 0
        for: 1m
        annotations:
          summary: "OSINT Suite is down"

      - alert: HighMemoryUsage
        expr: container_memory_usage_bytes > 2e9
        for: 5m
        annotations:
          summary: "High memory usage"
```

---

## 🧪 Testing

### 1. Unit Tests

```bash
# Run Python tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=api --cov=investigations --cov=security
```

### 2. Integration Tests

```bash
# Test API endpoints
curl -X POST http://localhost:8000/api/investigations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Test Investigation",
    "investigation_type": "domain",
    "targets": ["example.com"]
  }'
```

### 3. Load Testing

```bash
# Install locust
pip install locust

# Run load test
locust -f tests/load_test.py --host=http://localhost:8000
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. "OSINT_SECRET_KEY must be set" Error

**Problem:** Secret key not configured

**Solution:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Add to .env file
```

#### 2. "Connection refused" to Redis/PostgreSQL

**Problem:** Docker services not running

**Solution:**
```bash
docker-compose up -d redis postgres
docker-compose ps  # Verify services are running
```

#### 3. Frontend can't connect to API

**Problem:** CORS or API URL misconfiguration

**Solution:**
```bash
# Check .env file
VITE_API_URL=http://localhost:8000
CORS_ORIGINS=http://localhost:3000

# Rebuild frontend
cd web && npm run build
```

#### 4. Rate limit errors

**Problem:** Too many requests

**Solution:**
- Increase rate limits in `api/api_server.py`
- Or wait for rate limit window to reset

---

## 📚 Additional Resources

- [Security Guide](SECURITY_GUIDE.md) - Security best practices
- [API Documentation](http://localhost:8000/docs) - Interactive API docs (when running)
- [Docker Documentation](https://docs.docker.com/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

## 📞 Support

For issues or questions:
- GitHub Issues: `<repository-url>/issues`
- Documentation: [https://docs.yourdomain.com](https://docs.yourdomain.com)
- Email: support@yourdomain.com

---

**Last Updated:** 2025-10-03
**Version:** 2.0.0
