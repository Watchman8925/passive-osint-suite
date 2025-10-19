# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### Reporting Process

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues through one of the following channels:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](https://github.com/Watchman8925/passive-osint-suite/security/advisories)
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Email**
   - Send details to [security contact - to be configured]
   - Use PGP encryption if possible (key available upon request)
   - Include "SECURITY" in the subject line

3. **Private Disclosure via Issue**
   - Tag @Watchman8925 directly if needed
   - Mark as confidential if available

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What an attacker could achieve
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have a recommendation
- **Proof of Concept**: Code or screenshots demonstrating the issue
- **Your Contact Info**: So we can follow up with questions

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 7-14 days
  - Medium: 14-30 days
  - Low: 30-90 days

We will keep you informed throughout the process and credit you in the security advisory (unless you prefer to remain anonymous).

---

## Security Features

### Built-in Security

The Passive OSINT Suite includes several security features:

1. **No Hardcoded Secrets**
   - All credentials via environment variables
   - Vault integration for secure storage
   - See [docs/vault_integration.md](docs/vault_integration.md)

2. **Input Validation**
   - XSS prevention
   - SQL injection protection
   - Command injection prevention
   - See `src/passive_osint_common/safety.py`

3. **Rate Limiting**
   - DDoS protection on all endpoints
   - Automatic backoff and retry
   - Configurable rate limits

4. **Authentication & Authorization**
   - JWT-based authentication
   - Role-based access control (RBAC)
   - Secure session management

5. **Audit Trail**
   - Cryptographic signatures (Ed25519)
   - Immutable audit logs
   - OPSEC policy enforcement

6. **Network Security**
   - All operations via Tor (optional)
   - DNS-over-HTTPS (DoH) support
   - TLS/HTTPS for external APIs

### Automated Security Scanning

We run automated security scans on every commit:

- **Secret Scanning**: Gitleaks and TruffleHog
- **Dependency Scanning**: Safety and npm audit
- **Code Scanning**: CodeQL analysis
- **Container Scanning**: Trivy for Docker images
- **SAST**: Static analysis security testing

See `.github/workflows/` for CI/CD security workflows.

---

## Secure Development Practices

### For Contributors

When contributing code:

1. **Never commit secrets**
   - Use environment variables
   - Use `.env.example` as template
   - Add sensitive files to `.gitignore`

2. **Use safety helpers**
   - Always use `safe_request` from `src.passive_osint_common.safety`
   - Add input validation with `@input_validation` decorator
   - Handle exceptions with `@handle_exceptions` decorator

3. **Validate all inputs**
   - User inputs
   - API responses
   - File contents
   - Database queries

4. **Follow secure coding guidelines**
   - Principle of least privilege
   - Defense in depth
   - Fail securely
   - Don't trust user input

5. **Run security checks locally**
   ```bash
   # Install security tools
   pip install safety bandit
   
   # Check dependencies
   safety check
   
   # Security linting
   bandit -r modules/ src/
   
   # Run tests
   pytest tests/test_security_integration.py
   ```

### Code Review Checklist

Before merging PRs, verify:

- [ ] No hardcoded secrets or credentials
- [ ] Input validation on all user inputs
- [ ] Output encoding to prevent XSS
- [ ] Parameterized queries to prevent SQL injection
- [ ] Proper error handling without information leakage
- [ ] Timeouts on all network requests
- [ ] Rate limiting where applicable
- [ ] Security tests included
- [ ] Dependencies up-to-date and scanned

---

## Vault Integration

### Using HashiCorp Vault

For secure credential storage, we recommend HashiCorp Vault:

```python
from src.passive_osint_common.vault_client import VaultClient

# Initialize Vault client
vault = VaultClient()

# Store API key
vault.write_secret("passive-osint/api-keys/shodan", {
    "api_key": "your-key-here"
})

# Retrieve API key
secret = vault.read_secret("passive-osint/api-keys/shodan")
api_key = secret["api_key"]
```

See [docs/vault_integration.md](docs/vault_integration.md) for complete setup guide.

### Environment Variables

If not using Vault, use environment variables:

```bash
# .env file (add to .gitignore!)
SHODAN_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
DATABASE_PASSWORD=your-password-here
```

```python
import os

# In code
api_key = os.getenv("SHODAN_API_KEY")
if not api_key:
    raise ValueError("SHODAN_API_KEY not set in environment")
```

### Credential Rotation

Rotate credentials regularly:

- **API Keys**: Every 90 days
- **Passwords**: Every 90 days
- **Tokens**: Based on expiration policy
- **Certificates**: Before expiration

See [docs/vault_integration.md#rotation-policies](docs/vault_integration.md#rotation-policies) for automation.

---

## Handling Security Incidents

### If You Discover a Secret in Git History

1. **Immediately rotate the credential**
   - Change the password/key/token
   - Revoke access if possible
   - Create new credentials

2. **Report the incident**
   - Follow the vulnerability reporting process above
   - Include what was exposed and when

3. **Remove from history**
   - Use `scripts/clean_history.sh`
   - Follow force-push coordination process
   - See [CONTRIBUTING.md#force-push-coordination](CONTRIBUTING.md#force-push-coordination)

4. **Document the incident**
   - Create post-mortem
   - Update security policies
   - Improve detection/prevention

### Emergency Contacts

- **Project Maintainer**: @Watchman8925
- **Security Team**: [To be configured]
- **Emergency Email**: [To be configured]

---

## Security Advisories

### Viewing Advisories

View all security advisories:
- [GitHub Security Advisories](https://github.com/Watchman8925/passive-osint-suite/security/advisories)

### Subscribing to Updates

Stay informed about security updates:

1. **Watch the repository**
   - Click "Watch" → "Custom" → "Security alerts"

2. **Enable Dependabot alerts**
   - Automatic notifications for dependency vulnerabilities

3. **Follow releases**
   - Security patches announced in release notes

---

## Security Tools

### Recommended Tools

For local security testing:

```bash
# Dependency scanning
pip install safety pip-audit
safety check
pip-audit

# Secret scanning
brew install gitleaks  # macOS
gitleaks detect --source . --verbose

# Security linting
pip install bandit
bandit -r modules/ src/

# SAST
brew install semgrep
semgrep --config=auto

# Container scanning (if using Docker)
docker run aquasec/trivy image passive-osint-suite:latest
```

### CI/CD Security Workflows

Our GitHub Actions workflows automatically run:

- `.github/workflows/secret-scan.yml` - Secret scanning
- `.github/workflows/dependency-scan.yml` - Dependency scanning
- `.github/workflows/codeql.yml` - Code scanning
- `.github/workflows/trivy-scan.yml` - Container scanning

View results in the "Security" tab of the repository.

---

## Compliance

### Standards

We aim to comply with:

- **OWASP Top 10** - Web application security risks
- **CWE Top 25** - Most dangerous software weaknesses
- **NIST Cybersecurity Framework** - Security best practices
- **GDPR** - Data protection and privacy (where applicable)

### Audit Trail

All security-relevant actions are logged:

- Authentication attempts (success and failure)
- Authorization decisions
- Secret access (via Vault audit logs)
- Configuration changes
- Data access and modifications

Audit logs include:
- Timestamp
- User/actor
- Action performed
- Resource accessed
- Result (success/failure)
- Cryptographic signature

---

## Bug Bounty Program

We currently do not have a formal bug bounty program. However, we greatly appreciate security researchers who report vulnerabilities responsibly.

We will acknowledge security contributors:
- In the security advisory
- In the project CHANGELOG
- In the project README (Hall of Fame)

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [HashiCorp Vault Security Model](https://www.vaultproject.io/docs/internals/security)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

---

## Questions?

For security questions or concerns:
- Review this policy
- Check [docs/vault_integration.md](docs/vault_integration.md)
- Read [CONTRIBUTING.md](CONTRIBUTING.md)
- Open a security advisory (for vulnerabilities)
- Contact the maintainers (for questions)

---

**Last Updated**: 2025-01-19  
**Next Review**: 2025-04-19

Thank you for helping keep the Passive OSINT Suite secure! 🔒
