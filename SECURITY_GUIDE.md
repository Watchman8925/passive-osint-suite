# OSINT Suite Security Guide

## 🔒 Critical Security Improvements Implemented

This document outlines the security enhancements made to the OSINT Suite platform and provides guidance for secure deployment.

---

## ✅ Implemented Security Fixes

### 1. **Secret Management**

#### Before:
```python
SECRET_KEY = os.getenv("OSINT_SECRET_KEY", "change-this-secret-key-in-production-environment")
```

#### After:
```python
SECRET_KEY = os.getenv("OSINT_SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "change-this-secret-key-in-production-environment":
    raise ValueError("OSINT_SECRET_KEY environment variable must be set to a secure random value")
```

**Action Required:**
- Generate a secure secret key:
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
- Set in `.env` file:
  ```bash
  OSINT_SECRET_KEY=your_generated_key_here
  ```

---

### 2. **Input Validation**

All API endpoints now have comprehensive input validation using Pydantic validators:

```python
class InvestigationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    targets: List[str] = Field(..., min_items=1, max_items=100)

    @classmethod
    def validate_name(cls, v):
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\\';(){}]', '', v)
        if len(sanitized) != len(v):
            raise ValueError("Investigation name contains invalid characters")
        return sanitized.strip()
```

**Protection Against:**
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Excessive data submission

---

### 3. **Rate Limiting**

Implemented using `slowapi` library:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

@app.get("/api/health")
@limiter.limit("300/minute")
async def health_check(request: Request):
    ...
```

**Rate Limits:**
- Default: 100 requests/minute
- Health checks: 300 requests/minute
- Investigation creation: 15 requests/minute
- Module execution: 10 requests/5 minutes
- Report generation: 5 requests/5 minutes

---

### 4. **Development Endpoint Security**

The `/api/dev/token` endpoint is now strictly controlled:

```python
@app.post("/api/dev/token")
async def dev_token(...):
    # Strict environment check
    if AppConfig.ENVIRONMENT != "development":
        raise HTTPException(status_code=404, detail="Not found")

    if os.getenv("ENABLE_DEV_AUTH") != "1":
        raise HTTPException(status_code=403, detail="Dev auth disabled")
```

**Configuration:**
- NEVER enable in production
- Set `ENVIRONMENT=production` in production `.env`
- Keep `ENABLE_DEV_AUTH=0` or unset

---

### 5. **CORS Configuration**

Now configurable via environment variables:

```python
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
```

**Headers restricted to:**
- Content-Type
- Authorization
- X-Request-ID
- X-Client-Info

---

### 6. **Async File I/O**

Investigation storage now uses async file operations:

```python
import aiofiles

async def _flush(self):
    json_data = json.dumps(serialized, indent=2)
    async with aiofiles.open(self.index_file, 'w') as f:
        await f.write(json_data)
```

**Benefits:**
- Non-blocking I/O operations
- Better performance under load
- Prevents event loop blocking

---

### 7. **Health Check Endpoints**

Two health check endpoints implemented:

#### Basic Health Check
```
GET /api/health
Rate Limit: 300/minute
```

#### Detailed Health Check
```
GET /api/health/detailed
Rate Limit: 60/minute
```

Returns:
- Service connectivity status
- Response times
- Degraded services list

---

### 8. **Docker Security**

#### Before:
```yaml
GRAFANA_PASSWORD=${GRAFANA_PASSWORD:-admin123}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-secure_password}
```

#### After:
```yaml
GRAFANA_PASSWORD=${GRAFANA_PASSWORD:?GRAFANA_PASSWORD must be set in .env file}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set in .env file}
```

**Now requires** passwords to be explicitly set in `.env` file.

---

### 9. **Frontend Security**

#### Environment-based API URL
```typescript
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
```

#### Error Boundary
```typescript
<ErrorBoundary>
  <App />
</ErrorBoundary>
```

**Features:**
- Catches React errors gracefully
- Prevents white screen of death
- Shows user-friendly error messages
- Logs errors in development

---

## 🚀 Deployment Checklist

### Pre-Deployment

- [ ] Generate secure secret key
- [ ] Set all required environment variables
- [ ] Configure database passwords
- [ ] Set CORS origins to production domains
- [ ] Disable dev authentication (`ENABLE_DEV_AUTH=0`)
- [ ] Set `ENVIRONMENT=production`
- [ ] Review and restrict rate limits if needed

### Environment Variables Required

```bash
# Critical
OSINT_SECRET_KEY=<your-secure-key>
ENVIRONMENT=production
ENABLE_DEV_AUTH=0

# Database
POSTGRES_PASSWORD=<secure-password>
DATABASE_URL=postgresql://user:pass@host/db

# Monitoring
GRAFANA_PASSWORD=<secure-password>

# CORS
CORS_ORIGINS=https://yourdomain.com,https://api.yourdomain.com
```

### Security Hardening

1. **Enable HTTPS Only**
   - Use reverse proxy (nginx, Caddy)
   - Enforce TLS 1.2+
   - Use strong cipher suites

2. **Database Security**
   - Use connection pooling
   - Enable SSL for database connections
   - Implement connection limits

3. **Network Security**
   - Use firewall rules
   - Limit exposed ports
   - Use VPN for admin access

4. **Monitoring**
   - Enable security event logging
   - Set up alerts for:
     - Failed login attempts
     - Rate limit exceeded
     - Unusual API usage patterns
   - Monitor health check endpoints

---

## 🛡️ Security Best Practices

### 1. Secret Rotation
Rotate secrets regularly:
- Secret keys: Every 90 days
- Database passwords: Every 180 days
- API tokens: As per vendor recommendations

### 2. Access Control
- Implement Role-Based Access Control (RBAC)
- Use principle of least privilege
- Audit user permissions regularly

### 3. Data Protection
- Encrypt sensitive data at rest
- Use TLS for data in transit
- Implement data retention policies
- Secure investigation data files

### 4. Incident Response
- Have an incident response plan
- Monitor security alerts
- Keep backups of critical data
- Test disaster recovery procedures

### 5. Dependency Management
```bash
# Regular security audits
pip-audit
safety check
npm audit
```

---

## 📋 Security Testing

### Before Deployment

```bash
# Test with invalid secrets
OSINT_SECRET_KEY="" python api/api_server.py  # Should fail

# Test rate limiting
ab -n 1000 -c 10 http://localhost:8000/api/health

# Test CORS
curl -H "Origin: http://evil.com" http://localhost:8000/api/health

# Test input validation
curl -X POST http://localhost:8000/api/investigations \
  -H "Content-Type: application/json" \
  -d '{"name": "<script>alert(1)</script>"}'  # Should be rejected
```

---

## 🔍 Monitoring & Alerting

### Key Metrics to Monitor

1. **Security Events**
   - Failed authentication attempts
   - Rate limit violations
   - Input validation failures
   - Unauthorized access attempts

2. **Performance**
   - API response times
   - Database connection pool usage
   - File I/O operations
   - Memory and CPU usage

3. **Health**
   - Service availability
   - Database connectivity
   - External API status

### Alert Thresholds

- Failed logins: > 5 per hour per user
- Rate limit exceeded: > 10 per minute
- Service downtime: > 1 minute
- Database errors: > 5 per minute

---

## 📞 Security Contacts

For security vulnerabilities:
1. **Do not** open public issues
2. Email: security@yourdomain.com
3. Include:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)

---

## 🔄 Changelog

### 2025-10-03
- ✅ Removed hardcoded secrets
- ✅ Added input validation
- ✅ Implemented rate limiting
- ✅ Secured dev endpoints
- ✅ Fixed async file I/O
- ✅ Added health checks
- ✅ Implemented error boundaries
- ✅ Enforced Docker password requirements

---

**Last Updated:** 2025-10-03
**Version:** 2.0.0
