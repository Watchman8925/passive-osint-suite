# Production Deployment Guide

This guide covers production deployment of the Passive OSINT Suite with comprehensive security, monitoring, and operational considerations.

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **CPU**: 4+ cores recommended (2 cores minimum)
- **Memory**: 8GB RAM recommended (4GB minimum)
- **Storage**: 20GB available disk space
- **Network**: Internet connection for external API calls

### Required Software

```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Verify installation
docker --version
docker-compose --version
```

## Security-First Configuration

### 1. Environment Setup

```bash
# Clone repository
git clone <repository-url>
cd passive-osint-suite

# Copy environment template
cp .env.example .env

# Set secure file permissions
chmod 600 .env
```

### 2. Generate Production Keys

```bash
# Generate secure keys
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('OSINT_MASTER_KEY=' + secrets.token_urlsafe(32))"
```

### 3. Configure Production Environment

Edit `.env` with production values:

```bash
# Security Keys (USE GENERATED VALUES ABOVE)
SECRET_KEY=your_production_secret_key_32_chars_minimum
JWT_SECRET_KEY=your_production_jwt_secret_key_32_chars
ENCRYPTION_KEY=your_production_encryption_key_32_chars

# OSINT Suite Configuration
OSINT_MASTER_KEY=your_production_osint_master_key
OSINT_USE_KEYRING=false
OSINT_TEST_MODE=false
ENABLE_DEV_AUTH=0

# Database Configuration  
POSTGRES_USER=osint_prod_user
POSTGRES_PASSWORD=secure_production_database_password
POSTGRES_DB=osint_prod_db

# Monitoring Credentials
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=secure_grafana_admin_password
GRAFANA_PASSWORD=secure_grafana_password

# Tor Configuration
TOR_CONTROL_PORT=9051
TOR_SOCKS_PORT=9050

# API Keys (Add your actual keys)
SHODAN_API_KEY=your_shodan_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

## Deployment Options

### Standard Production Deployment

```bash
# Start core services
docker-compose up -d

# Verify services
docker-compose ps
docker-compose logs osint-suite
```

### Full Stack with Monitoring

```bash
# Start with comprehensive monitoring
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d

# Check all services
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml ps
```

## Production Service Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| OSINT Suite API | http://localhost:8000 | Main application |
| API Documentation | http://localhost:8000/docs | Interactive API docs |
| Health Check | http://localhost:8000/api/health | Service health |
| Grafana Dashboard | http://localhost:3000 | Monitoring dashboards |
| Prometheus | http://localhost:9090 | Metrics collection |
| PostgreSQL | localhost:5432 | Database (internal) |
| Redis | localhost:6379 | Cache (internal) |

## Security Hardening

### 1. Firewall Configuration

```bash
# Configure UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp        # SSH
sudo ufw allow 8000/tcp      # OSINT Suite API
sudo ufw allow 3000/tcp      # Grafana (if external access needed)
sudo ufw enable
```

### 2. SSL/TLS with Reverse Proxy

#### Nginx Configuration

```bash
# Install nginx and certbot
sudo apt install nginx certbot python3-certbot-nginx

# Configure SSL
sudo certbot --nginx -d your-domain.com
```

Example nginx configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### 3. Network Security

```bash
# Create isolated Docker network
docker network create osint_production

# Update docker-compose.yml to use custom network
```

### 4. Regular Security Audits

```bash
# Run security audit script
python scripts/security_audit.py

# Check for vulnerabilities
docker run --rm -v $(pwd):/app clair-scanner:latest
```

## Monitoring and Alerting

### 1. Grafana Dashboard Setup

1. Access Grafana at https://your-domain.com:3000
2. Login with admin credentials from `.env`
3. Import OSINT Suite dashboard
4. Configure alerting rules

### 2. Log Management

```bash
# Configure log rotation
sudo vim /etc/logrotate.d/docker-containers

# Content:
/var/lib/docker/containers/*/*.log {
    rotate 5
    weekly
    compress
    size 10M
    missingok
    delaycompress
    copytruncate
}
```

### 3. Health Monitoring

Set up automated health checks:

```bash
# Create health check script
#!/bin/bash
HEALTH_URL="http://localhost:8000/api/health"
if ! curl -f "$HEALTH_URL" > /dev/null 2>&1; then
    echo "OSINT Suite health check failed" | mail -s "Alert: OSINT Suite Down" admin@yourcompany.com
fi
```

Add to crontab:
```bash
crontab -e
# Add: */5 * * * * /path/to/health-check.sh
```

## Backup and Recovery

### 1. Database Backup

```bash
#!/bin/bash
# backup-database.sh
BACKUP_DIR="/opt/backups/osint"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup PostgreSQL
docker-compose exec -T postgres pg_dump -U osint_prod_user osint_prod_db | gzip > "$BACKUP_DIR/db_backup_$DATE.sql.gz"

# Backup Redis (if persistence enabled)
docker-compose exec redis redis-cli --rdb - | gzip > "$BACKUP_DIR/redis_backup_$DATE.rdb.gz"

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete
```

### 2. Configuration Backup

```bash
#!/bin/bash
# backup-config.sh
BACKUP_DIR="/opt/backups/osint"
DATE=$(date +%Y%m%d_%H%M%S)

tar -czf "$BACKUP_DIR/config_backup_$DATE.tar.gz" \
    .env \
    docker-compose.yml \
    docker-compose.monitoring.yml \
    docker/ \
    logs/ \
    output/ \
    policies/
```

### 3. Automated Backup Schedule

```bash
# Add to root crontab
0 2 * * * /opt/scripts/backup-database.sh
0 3 * * * /opt/scripts/backup-config.sh
```

## Performance Optimization

### 1. Resource Limits

Add resource limits to docker-compose.yml:

```yaml
services:
  osint-suite:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          memory: 2G
```

### 2. Database Optimization

```sql
-- PostgreSQL optimizations
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
SELECT pg_reload_conf();
```

### 3. Redis Optimization

```bash
# Add to docker-compose.yml redis service
command: >
  --maxmemory 512mb
  --maxmemory-policy allkeys-lru
  --save 900 1
  --save 300 10
```

## Scaling Considerations

### 1. Horizontal Scaling

```bash
# Scale OSINT Suite instances
docker-compose up -d --scale osint-suite=3

# Add load balancer configuration
```

### 2. Load Balancing

Example HAProxy configuration:

```
frontend osint_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/osint.pem
    redirect scheme https if !{ ssl_fc }
    default_backend osint_backend

backend osint_backend
    balance roundrobin
    option httpchk GET /api/health
    server osint1 127.0.0.1:8001 check
    server osint2 127.0.0.1:8002 check
    server osint3 127.0.0.1:8003 check
```

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   # Check logs
   docker-compose logs service-name
   
   # Check configuration
   docker-compose config
   
   # Verify environment variables
   docker-compose exec service-name env
   ```

2. **Database Connection Issues**
   ```bash
   # Test database connectivity
   docker-compose exec postgres psql -U osint_prod_user -d osint_prod_db
   
   # Check database logs
   docker-compose logs postgres
   ```

3. **High Memory Usage**
   ```bash
   # Monitor resource usage
   docker stats
   
   # Check application logs for memory leaks
   docker-compose logs osint-suite | grep -i memory
   ```

### Emergency Procedures

1. **Service Recovery**
   ```bash
   # Stop all services
   docker-compose down
   
   # Start with fresh containers
   docker-compose up -d --force-recreate
   ```

2. **Database Recovery**
   ```bash
   # Restore from backup
   gunzip -c /opt/backups/osint/db_backup_YYYYMMDD_HHMMSS.sql.gz | \
   docker-compose exec -T postgres psql -U osint_prod_user osint_prod_db
   ```

## Maintenance Schedule

### Daily
- Monitor logs for errors
- Check disk space usage
- Verify backup completion

### Weekly
- Review security audit results
- Update Docker images
- Analyze performance metrics

### Monthly
- Rotate SSL certificates (automated)
- Review and update security policies
- Capacity planning review

### Quarterly
- Full security assessment
- Update dependencies
- Disaster recovery testing

## Production Checklist

Before going live:

- [ ] All environment variables set with strong, unique values
- [ ] SSL/TLS configured and tested
- [ ] Firewall rules implemented and tested
- [ ] Backup strategy implemented and tested
- [ ] Monitoring dashboards configured
- [ ] Log rotation configured
- [ ] Health checks configured
- [ ] Security audit passed with no critical issues
- [ ] Performance testing completed
- [ ] Disaster recovery plan documented and tested
- [ ] Team trained on operational procedures

## Support and Maintenance

For production issues:

1. **Immediate Response**
   - Check service health: `curl https://your-domain.com/api/health`
   - Review logs: `docker-compose logs --tail=100`
   - Check resource usage: `docker stats`

2. **Security Issues**
   - Run security audit: `python scripts/security_audit.py`
   - Check for unauthorized access in logs
   - Verify SSL certificate validity

3. **Performance Issues**
   - Monitor Grafana dashboards
   - Check database performance
   - Review application metrics

---

For additional support, ensure your team has access to:
- This deployment guide
- Security audit procedures
- Backup and recovery procedures
- Emergency contact information