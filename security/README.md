# OSINT Suite Security Framework

A comprehensive enterprise-grade security framework for the OSINT Suite, providing authentication, authorization, data protection, and monitoring capabilities.

## Overview

The security framework consists of four main components:

1. **RBAC Manager** (`rbac_manager.py`) - Role-based access control with user management
2. **Data Access Control** (`data_access_control.py`) - Data classification and access policies
3. **Security Monitor** (`security_monitor.py`) - Security event monitoring and alerting
4. **Security API** (`security_api.py`) - FastAPI integration with authentication middleware

## Features

### 🔐 Authentication & Authorization
- JWT-based authentication with configurable expiration
- Role-based access control (RBAC) with hierarchical permissions
- Session management with automatic cleanup
- API key authentication for programmatic access
- Multi-factor authentication support (extensible)

### 🛡️ Data Protection
- Data classification levels (Public, Internal, Confidential, Secret)
- Access policies based on user roles and clearance levels
- Data retention policies with automatic cleanup
- Encryption support for sensitive data
- Audit logging for all data access

### 📊 Security Monitoring
- Real-time security event logging
- Automated alert generation for suspicious activities
- Security risk assessment and reporting
- Compliance reporting for security standards
- Configurable monitoring thresholds

### 🚨 Threat Detection
- Failed login attempt monitoring
- Privilege escalation detection
- Data exfiltration pattern recognition
- Suspicious access pattern analysis
- Automated incident response recommendations

## Installation

The security framework is included with the OSINT Suite. No additional installation required.

```bash
# Install OSINT Suite with security dependencies
pip install -r requirements.txt
```

## Quick Start

### 1. Initialize Security Framework

```python
from security.rbac_manager import rbac_manager
from security.data_access_control import data_access_control
from security.security_monitor import security_monitor
from security.security_api import init_security_middleware

# Initialize components
rbac_manager.initialize()
data_access_control.initialize()
security_monitor.start_monitoring()

# Setup FastAPI security (if using web interface)
from fastapi import FastAPI
app = FastAPI()
app = init_security_middleware(app)
```

### 2. Create Admin User

```python
from security.rbac_manager import rbac_manager

# Create first admin user
admin = rbac_manager.create_user(
    username="admin",
    password="secure_password_123",
    email="admin@organization.com",
    full_name="System Administrator",
    role="admin"
)

print(f"Admin user created with ID: {admin.id}")
```

### 3. Setup Roles and Permissions

```python
# Add roles with permissions
rbac_manager.add_role("analyst", [
    "intelligence:read",
    "data:read",
    "reports:create"
])

rbac_manager.add_role("investigator", [
    "intelligence:*",
    "data:*",
    "cases:*"
])

rbac_manager.add_role("auditor", [
    "audit:read",
    "security:read",
    "reports:read"
])
```

## API Usage

### Authentication Endpoints

#### Login
```bash
POST /auth/login
Content-Type: application/json

{
  "username": "analyst",
  "password": "secure_password"
}
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 86400,
  "user": {
    "id": "user123",
    "username": "analyst",
    "role": "analyst",
    "email": "analyst@org.com"
  }
}
```

#### Using JWT Token
```bash
GET /api/intelligence/reports
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### User Management

#### Create User
```bash
POST /users
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "username": "new_analyst",
  "password": "secure_password_123",
  "email": "analyst@org.com",
  "full_name": "New Analyst",
  "role": "analyst"
}
```

#### List Users
```bash
GET /users?skip=0&limit=50
Authorization: Bearer <admin_token>
```

### API Key Management

#### Create API Key
```bash
POST /auth/api-keys
Authorization: Bearer <user_token>
Content-Type: application/json

{
  "name": "Intelligence API Access",
  "permissions": ["intelligence:read", "data:read"],
  "expires_in_days": 365
}
```

#### Using API Key
```bash
GET /api/intelligence/search?q=example
X-API-Key: your_api_key_here
```

## Data Protection

### Classifying Data

```python
from security.data_access_control import data_access_control

# Create classified data object
intelligence_report = data_access_control.create_data_object(
    name="cyber_threat_report",
    data_type="intelligence_report",
    classification="confidential",
    owner_id="analyst123",
    content={
        "title": "Advanced Persistent Threat Analysis",
        "threat_level": "high",
        "indicators": ["malware_hash", "c2_server"]
    }
)
```

### Access Control

```python
# Check if user can access data
can_access = data_access_control.check_access(
    user_id="analyst123",
    data_id=intelligence_report.id,
    action="read"
)

if can_access:
    print("Access granted")
else:
    print("Access denied")
```

### Data Retention

```python
# Set retention policy
data_access_control.set_retention_policy(
    data_id=intelligence_report.id,
    retention_days=2555  # 7 years
)

# Apply retention policies (removes expired data)
data_access_control.apply_data_retention()
```

## Security Monitoring

### Logging Security Events

```python
from security.security_monitor import security_monitor

# Log security event
security_monitor.log_security_event(
    event_type="data_access",
    severity="low",
    user_id="analyst123",
    details={
        "data_id": "intel_001",
        "action": "read",
        "source": "web_interface"
    }
)
```

### Security Reports

```python
# Get security report for last 7 days
report = security_monitor.get_security_report(days=7)

print(f"Total events: {report['total_events']}")
print(f"Risk assessment: {report['risk_assessment']}")
print(f"Security recommendations: {report['recommendations']}")
```

### Compliance Reporting

```python
# Get compliance report
compliance = security_monitor.get_compliance_report()

print(f"Overall compliance: {compliance['overall_compliance']}")
for standard, status in compliance['standards'].items():
    print(f"{standard}: {status['status']}")
```

## Configuration

### Security Settings

Create a `security/config.json` file:

```json
{
  "jwt": {
    "secret_key": "your-super-secret-jwt-key-change-in-production",
    "algorithm": "HS256",
    "expiration_hours": 24
  },
  "password_policy": {
    "min_length": 12,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digits": true,
    "require_special_chars": true
  },
  "session": {
    "max_concurrent_sessions": 5,
    "session_timeout_hours": 8,
    "cleanup_interval_minutes": 30
  },
  "monitoring": {
    "alert_thresholds": {
      "failed_logins_per_hour": 5,
      "suspicious_access_per_hour": 10,
      "data_access_violations_per_hour": 3
    },
    "retention_days": {
      "security_events": 90,
      "security_alerts": 365,
      "audit_logs": 2555
    }
  }
}
```

### Environment Variables

```bash
# JWT Configuration
export JWT_SECRET_KEY="your-production-jwt-secret"
export JWT_EXPIRATION_HOURS=24

# Database Configuration
export SECURITY_DB_URL="postgresql://user:pass@localhost/security_db"

# Monitoring Configuration
export SECURITY_MONITOR_ENABLED=true
export SECURITY_ALERT_EMAIL="security@organization.com"
```

## Security Best Practices

### 1. Password Security
- Use strong, unique passwords
- Implement password rotation policies
- Enable multi-factor authentication
- Use password managers for users

### 2. Access Control
- Follow principle of least privilege
- Regularly review user permissions
- Implement segregation of duties
- Use role-based access control consistently

### 3. Data Protection
- Classify data appropriately
- Encrypt sensitive data at rest and in transit
- Implement data retention policies
- Regular security audits

### 4. Monitoring & Response
- Monitor security events continuously
- Set up automated alerts
- Have incident response procedures
- Regular security training

## Testing

Run the security test suite:

```bash
# Run all security tests
python -m pytest security/test_security.py -v

# Run specific test categories
python -m pytest security/test_security.py::TestRBACManager -v
python -m pytest security/test_security.py::TestDataAccessControl -v
python -m pytest security/test_security.py::TestSecurityMonitor -v
```

## Troubleshooting

### Common Issues

#### Authentication Fails
```python
# Check user credentials
user = rbac_manager.get_user_by_username("username")
if user:
    print(f"User exists: {user.is_active}")
else:
    print("User not found")
```

#### Permission Denied
```python
# Check user permissions
permissions = rbac_manager.get_user_permissions("user_id")
print("User permissions:", permissions)

# Check role permissions
role_perms = rbac_manager.get_role_permissions("role_name")
print("Role permissions:", role_perms)
```

#### Security Alerts Not Working
```python
# Check monitoring status
print("Monitoring active:", security_monitor.monitoring_active)
print("Total events:", len(security_monitor.security_events))
print("Total alerts:", len(security_monitor.security_alerts))
```

## API Reference

### Authentication Endpoints

- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `GET /auth/me` - Get current user info
- `POST /auth/api-keys` - Create API key
- `GET /auth/api-keys` - List API keys
- `DELETE /auth/api-keys/{key_id}` - Revoke API key

### User Management Endpoints

- `POST /users` - Create user
- `GET /users` - List users
- `PUT /users/{user_id}` - Update user
- `DELETE /users/{user_id}` - Delete user

### Security Monitoring Endpoints

- `GET /security/report` - Get security report
- `GET /security/compliance` - Get compliance report
- `GET /security/alerts` - Get security alerts

## Contributing

When contributing to the security framework:

1. Follow security best practices
2. Add comprehensive tests
3. Update documentation
4. Ensure backward compatibility
5. Run security audits before major changes

## License

This security framework is part of the OSINT Suite and follows the same licensing terms.

## Support

For security-related issues or questions:
- Check the troubleshooting section
- Review security logs and alerts
- Contact the security team
- Refer to the main OSINT Suite documentation