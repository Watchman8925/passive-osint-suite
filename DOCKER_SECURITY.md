# Docker Security Guide

This document outlines the security scanning and hardening practices implemented for the Passive OSINT Suite Docker containers.

## 🔒 Security Workflows

### Trivy Security Scan

**Workflow:** `.github/workflows/trivy-scan.yml`

Trivy scans the Docker image for known vulnerabilities in:
- Operating system packages
- Application dependencies
- Python packages

**Features:**
- Scans for CRITICAL and HIGH severity vulnerabilities
- Uploads results to GitHub Security tab (SARIF format)
- Runs on push, pull requests, and daily schedule
- Ignores unfixed vulnerabilities to reduce noise
- 10-minute timeout to handle large images

**Run locally:**
```bash
# Build the image
docker build -t passive-osint-suite:scan .

# Scan with Trivy
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  passive-osint-suite:scan
```

### Dockle Container Security

**Workflow:** `.github/workflows/container-security.yml`

Dockle checks for container image best practices and CIS Docker Benchmarks compliance:
- Dockerfile best practices
- Security configurations
- Image layer optimization
- User and permission settings

**Features:**
- Automatic disk space cleanup (removes 5+ GB of unused files)
- Docker system prune before build
- Scans against CIS Docker Benchmarks
- Uploads results as artifacts

**Run locally:**
```bash
# Build the image
docker build -t passive-osint-suite:test .

# Scan with Dockle
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest \
  --exit-code 1 \
  --exit-level fatal \
  passive-osint-suite:test
```

## 🛡️ Security Best Practices

### Dockerfile Security

1. **Multi-stage build:** Reduces final image size by excluding build dependencies
2. **Non-root user:** Container runs as `osint` user, not root
3. **Minimal base image:** Uses `python:3.12-slim` for smaller attack surface
4. **HEALTHCHECK:** Validates container health at runtime
5. **No secrets in layers:** All sensitive data passed via environment variables
6. **OCI labels:** Comprehensive metadata for compliance tracking

### Ignored Checks

Some security checks are intentionally ignored as they are already addressed or not applicable:

**.trivyignore:**
- Add specific CVE IDs that are acceptable or false positives
- Document the reason for each ignore

**.dockleignore:**
- `CIS-DI-0001`: We already use a non-root user
- `CIS-DI-0005`: Content trust is handled in CI/CD
- `CIS-DI-0006`: HEALTHCHECK is present in Dockerfile
- `DKL-DI-0006`: Specific versions are used in requirements.txt

## 📊 Security Scan Results

Results from both Trivy and Dockle scans are automatically uploaded:

- **Trivy:** GitHub Security tab (Code scanning alerts)
- **Dockle:** GitHub Actions artifacts (JSON format)

## 🔧 Addressing Vulnerabilities

### Critical/High Vulnerabilities

1. Review the vulnerability in GitHub Security tab or Trivy output
2. Check if a fix is available:
   - Update base image version
   - Update Python package version in requirements.txt
   - Update system packages in Dockerfile
3. If no fix available, add to `.trivyignore` with justification
4. Document the risk assessment and mitigation plan

### Container Configuration Issues

1. Review Dockle results in Actions artifacts
2. Fix issues in Dockerfile:
   - Add missing security configurations
   - Optimize image layers
   - Update user/permission settings
3. If issue is acceptable, add to `.dockleignore` with justification

## 🚀 Running Security Scans Locally

### Complete Security Check

```bash
# 1. Build the image
docker build -t passive-osint-suite:scan .

# 2. Run Trivy scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --format table \
  passive-osint-suite:scan

# 3. Run Dockle scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest \
  --exit-level warn \
  passive-osint-suite:scan

# 4. Test container health
docker run -d --name osint-test passive-osint-suite:scan
sleep 60
docker inspect --format='{{json .State.Health}}' osint-test | jq .
docker stop osint-test && docker rm osint-test
```

### Scan Specific Layers

```bash
# Scan only OS packages
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  passive-osint-suite:scan

# Scan only Python packages
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image \
  --scanners vuln \
  --pkg-types python-pkg \
  passive-osint-suite:scan
```

## 🔄 Continuous Security

- **Daily scans:** Trivy runs daily at 2 AM UTC to catch new vulnerabilities
- **PR checks:** Both Trivy and Dockle run on all pull requests
- **Security tab:** Monitor vulnerabilities in GitHub Security tab
- **Automated updates:** Consider using Dependabot for dependency updates

## 📚 References

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Dockle Documentation](https://github.com/goodwithtech/dockle)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

## 🆘 Troubleshooting

### Workflow Fails with "Out of Disk Space"

The Dockle workflow includes automatic cleanup, but if issues persist:
1. Check the workflow run logs for disk space
2. Increase cleanup in workflow (remove more directories)
3. Use smaller test image or optimize Dockerfile

### Permission Denied when Accessing Docker Image

Ensure the image is built successfully before scanning:
1. Check Docker build logs for errors
2. Verify image exists: `docker images | grep passive-osint-suite`
3. Use correct image tag in scan commands

### False Positives in Security Scans

Add vulnerabilities to ignore files with proper justification:
1. `.trivyignore` for Trivy CVEs
2. `.dockleignore` for Dockle checks
3. Document why each ignore is acceptable
4. Review ignores periodically for updates

## ✅ Security Checklist

- [ ] Dockerfile uses non-root user
- [ ] Multi-stage build reduces image size
- [ ] HEALTHCHECK instruction present
- [ ] No secrets in Docker layers
- [ ] Trivy scan passes or has documented ignores
- [ ] Dockle scan passes or has documented ignores
- [ ] Security scan results reviewed weekly
- [ ] Dependencies updated monthly
- [ ] Base image updated when security patches available
