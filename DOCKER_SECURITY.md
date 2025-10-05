<<<<<<< HEAD
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
=======
# Docker Security and Optimization Guide

## Overview

This document describes the security measures and optimizations implemented in the Passive OSINT Suite Docker image.

## Security Improvements

### 1. Base Image Security

**Pinned Base Image**
- The Dockerfile uses a pinned base image digest to ensure reproducibility and prevent supply chain attacks
- Current base: `python:3.12-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f`
- Benefits:
  - Guarantees the exact same base image is used every time
  - Prevents automatic updates that might introduce vulnerabilities
  - Provides a clear audit trail

**Updating the Base Image**
To update the base image:
```bash
# Pull the latest version
docker pull python:3.12-slim

# Get the digest
docker inspect python:3.12-slim --format='{{index .RepoDigests 0}}'

# Update the Dockerfile with the new digest
```

### 2. Multi-Stage Build

The Dockerfile uses a multi-stage build to:
- **Reduce final image size**: Build dependencies are not included in the production image
- **Minimize attack surface**: Only runtime dependencies are present in the final image
- **Improve security**: Separate build and runtime environments

**Stages:**
1. **Builder Stage**: Installs build tools and compiles Python packages
2. **Production Stage**: Contains only runtime dependencies and application code

### 3. Non-Root User

**Security Principle: Least Privilege**
- The container runs as the `osint` user (non-root)
- User ID and group are created during build
- All files are owned by the `osint` user
- This prevents privilege escalation attacks

### 4. Minimal Runtime Dependencies

**Installed Packages:**
- `curl`: For health checks and HTTP operations
- `procps`: For process management utilities
- `ca-certificates`: For SSL/TLS certificate validation
- `libexpat1`: Runtime library dependency

**Security Benefits:**
- Reduced attack surface
- Fewer potential vulnerabilities
- Smaller image size
- Faster updates and patching

### 5. No Secrets in Image

**Protected Files (via .dockerignore):**
- Environment files (`.env`, `.env.*`)
- Private keys (`*.key`, `*.pem`, `*.p12`, `*.pfx`)
- Credential files (`*credential*`)
- Secret files (`*secret*`)
- Password files (`*password*`)
- Logs and temporary files

**Best Practices:**
- Use environment variables for secrets
- Mount secrets as Docker secrets or volumes
- Never hardcode credentials in Dockerfile or application code

### 6. Dependency Management

**Python Dependencies:**
- All Python packages are pinned in `requirements.txt`
- pip is upgraded to a specific version (`pip==25.2`)
- `--no-cache-dir` flag prevents caching sensitive data

**System Dependencies:**
- Minimal set of runtime packages
- Regular security updates via `apt-get upgrade`
- Cleanup of package lists to reduce image size

## Vulnerability Scanning

### Automated Scanning

The repository includes automated security scanning through GitHub Actions:

1. **Hadolint** (Dockerfile Linting)
   - Workflow: `.github/workflows/docker-lint.yml`
   - Checks Dockerfile best practices
   - Runs on every push and PR

2. **Trivy** (Vulnerability Scanning)
   - Workflow: `.github/workflows/trivy-scan.yml`
   - Scans for known vulnerabilities (HIGH/CRITICAL)
   - Uploads results to GitHub Security tab
   - Runs on push, PR, and weekly schedule

3. **Dockle** (Best Practices)
   - Workflow: `.github/workflows/container-security.yml`
   - Checks Docker image best practices
   - Fails on critical findings

### Manual Scanning

**Using the Security Scanner Script:**
```bash
# Build the image first
docker build -t passive-osint-suite:latest .

# Run comprehensive security scan
./scripts/scan_docker_image.sh passive-osint-suite:latest

# Results will be saved in .security-scan/ directory
```

**Individual Tools:**

```bash
# Hadolint - Dockerfile linting
docker run --rm -i hadolint/hadolint < Dockerfile

# Trivy - Vulnerability scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity HIGH,CRITICAL passive-osint-suite:latest

# Dockle - Best practices check
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest passive-osint-suite:latest
```

## Image Optimization

### Size Reduction Techniques

1. **Multi-stage builds**: Only runtime files in final image
2. **Slim base image**: Using `python:3.12-slim` instead of full Python image
3. **Cleanup**: Remove package lists and build artifacts
4. **No cache**: `--no-cache-dir` for pip installations
5. **.dockerignore**: Exclude unnecessary files from build context

### Layer Optimization

- Combined RUN commands where appropriate
- Strategic layer ordering (least to most frequently changed)
- Efficient COPY operations with correct ownership

## Runtime Security

### Environment Variables

Safe environment variables set in the image:
```dockerfile
ENV PYTHONPATH=/app
ENV OSINT_USE_KEYRING=false
ENV OSINT_TEST_MODE=false
ENV HF_HOME=/home/osint/.cache/huggingface
```

**Sensitive variables should be passed at runtime:**
```bash
docker run -e SECRET_KEY=xxx -e API_KEY=yyy ...
```

### Health Checks

The image includes a health check that:
- Verifies the application is running
- Checks that modules are loaded correctly
- Runs every 30 seconds with 60s start period
- Helps orchestrators detect failures

### Hardened Runtime

For production deployments, use hardened runtime flags:

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
  passive-osint-suite:latest
```

Or use the provided hardened Docker Compose override:
```bash
docker compose -f docker-compose.yml -f docker-compose.override.hardened.yml up -d
```

## Maintenance and Updates

### Regular Updates

1. **Update base image** (monthly or after security advisories):
   ```bash
   docker pull python:3.12-slim
   # Update Dockerfile with new digest
   ```

2. **Update dependencies** (monthly):
   ```bash
   # Review and update requirements.txt
   pip-audit  # Check for known vulnerabilities
   ```

3. **Scan for vulnerabilities** (weekly):
   ```bash
   ./scripts/scan_docker_image.sh
   ```

### Security Monitoring

- Monitor GitHub Security tab for vulnerability alerts
- Review Dependabot alerts for Python dependencies
- Subscribe to security advisories for base images
- Run automated scans on schedule (configured in workflows)

## Compliance and Best Practices

### NIST Security Standards

The Docker image follows NIST container security guidelines:
- ✅ Use trusted base images
- ✅ Run as non-root user
- ✅ Scan for vulnerabilities regularly
- ✅ Keep software up to date
- ✅ Minimize installed packages
- ✅ Don't include secrets in images
- ✅ Use read-only file systems when possible

### CIS Docker Benchmark

Compliance with CIS Docker Benchmark:
- ✅ 4.1: Create a user for the container
- ✅ 4.2: Use trusted base images
- ✅ 4.3: Do not install unnecessary packages
- ✅ 4.5: Enable Content trust
- ✅ 4.6: Add HEALTHCHECK instruction
- ✅ 4.7: Do not use update instructions alone
- ✅ 4.9: Use COPY instead of ADD

## Troubleshooting

### Build Issues

**SSL Certificate Errors:**
```bash
# If behind corporate proxy, set build args
docker build --build-arg HTTP_PROXY=http://proxy:port \
  --build-arg HTTPS_PROXY=http://proxy:port \
  -t passive-osint-suite:latest .
```

**Dependency Conflicts:**
```bash
# Rebuild with no cache
docker build --no-cache -t passive-osint-suite:latest .
```

### Runtime Issues

**Permission Errors:**
- Ensure volumes are writable by the `osint` user
- Check file ownership in mounted volumes

**Module Loading Failures:**
- Check logs: `docker logs <container-id>`
- Verify all dependencies are installed
- Check health status: `docker exec <container-id> python -c "from modules import MODULE_REGISTRY; print(len(MODULE_REGISTRY))"`

## Additional Resources

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [NIST SP 800-190: Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

## Summary

The Passive OSINT Suite Docker image implements comprehensive security measures:

1. ✅ **Pinned base image** for reproducibility and security
2. ✅ **Multi-stage build** to minimize attack surface
3. ✅ **Non-root user** for least privilege
4. ✅ **Minimal dependencies** to reduce vulnerabilities
5. ✅ **No secrets** in the image
6. ✅ **Automated vulnerability scanning** with Trivy, Hadolint, and Dockle
7. ✅ **Comprehensive security documentation**
8. ✅ **Security scanning scripts** for manual validation

These measures ensure the Docker image is secure, optimized, and follows industry best practices.
>>>>>>> origin/main
