#!/usr/bin/env python3
"""
Security Audit Script for Passive OSINT Suite
Performs comprehensive security checks and hardening validation
"""

import os
import re
import subprocess
import sys
from typing import Dict, List


def check_file_permissions() -> List[str]:
    """Check for overly permissive file permissions"""
    issues = []
    sensitive_files = [
        "config/config.ini",
        "config.ini",
        ".env",
        "secrets.enc",
        "encryption.key",
    ]

    for file_path in sensitive_files:
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            mode = oct(stat.st_mode)[-3:]
            if mode != "600":  # Should be read/write owner only
                issues.append(f"File {file_path} has permissions {mode}, should be 600")

    return issues


def scan_for_hardcoded_secrets() -> List[str]:
    """Scan for potential hardcoded secrets in code"""
    issues = []

    # Patterns that might indicate hardcoded secrets
    secret_patterns = [
        (
            r'(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*["\'][^"\']{20,}["\']',
            "Potential hardcoded secret",
        ),
        (r"(?i)(sk-[a-zA-Z0-9]{48})", "OpenAI API key pattern"),
        (r"(?i)(ghp_[a-zA-Z0-9]{36})", "GitHub personal access token"),
        (r"(?i)(xoxb-[a-zA-Z0-9-]+)", "Slack bot token"),
        (r"(?i)(AKIA[0-9A-Z]{16})", "AWS access key ID"),
        (r"(?i)([0-9a-f]{32})", "MD5 hash (possible secret)"),
        (r"(?i)([0-9a-f]{40})", "SHA1 hash (possible secret)"),
    ]

    exclude_files = {
        ".git",
        "__pycache__",
        "node_modules",
        ".env.example",
        "security_audit.py",
    }
    exclude_extensions = {".pyc", ".log", ".md", ".rst", ".txt"}

    for root, dirs, files in os.walk("."):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_files]

        for file in files:
            if any(file.endswith(ext) for ext in exclude_extensions):
                continue

            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern, description in secret_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        issues.append(
                            f"{file_path}: {description} - {len(matches)} matches"
                        )

            except (UnicodeDecodeError, PermissionError):
                continue

    return issues


def check_dependencies() -> List[str]:
    """Check for known vulnerable dependencies"""
    issues = []

    try:
        # Check if safety is available for dependency scanning
        result = subprocess.run(
            ["pip", "list", "--format=json"], capture_output=True, text=True, check=True
        )

        # Basic check for commonly vulnerable packages
        vulnerable_patterns = [
            "django<3.2",
            "flask<2.0",
            "requests<2.25",
            "pillow<8.0",
            "cryptography<3.0",
        ]

        pip_list = result.stdout
        for pattern in vulnerable_patterns:
            if pattern.split("<")[0] in pip_list.lower():
                issues.append(f"Potentially vulnerable dependency detected: {pattern}")

    except subprocess.CalledProcessError:
        issues.append("Could not check dependencies - pip list failed")

    return issues


def check_docker_security() -> List[str]:
    """Check Docker configurations for security issues"""
    issues = []

    docker_files = ["Dockerfile", "docker-compose.yml", "docker-compose.monitoring.yml"]

    for docker_file in docker_files:
        if not os.path.exists(docker_file):
            continue

        with open(docker_file, "r") as f:
            content = f.read()

        # Check for common Docker security issues
        if "USER root" in content or "user: root" in content:
            issues.append(f"{docker_file}: Running as root user")

        if "--privileged" in content or "privileged: true" in content:
            issues.append(f"{docker_file}: Using privileged mode")

        if "/var/run/docker.sock" in content:
            issues.append(f"{docker_file}: Mounting Docker socket")

        # Check for hardcoded passwords in docker-compose
        if "password" in content.lower() and "${" not in content:
            password_lines = [
                line.strip()
                for line in content.split("\n")
                if "password" in line.lower() and "${" not in line
            ]
            if password_lines:
                issues.append(
                    f"{docker_file}: Potential hardcoded passwords: {password_lines}"
                )

    return issues


def check_cors_configuration() -> List[str]:
    """Check CORS configuration for security"""
    issues = []

    api_files = ["api/api_server.py", "api_server.py"]

    for api_file in api_files:
        if not os.path.exists(api_file):
            continue

        with open(api_file, "r") as f:
            content = f.read()

        # Check for overly permissive CORS
        if 'allow_origins=["*"]' in content:
            issues.append(f"{api_file}: CORS allows all origins (*)")

        if "allow_credentials=True" in content and 'allow_origins=["*"]' in content:
            issues.append(f"{api_file}: CORS allows credentials with wildcard origins")

    return issues


def check_environment_variables() -> List[str]:
    """Check for missing critical environment variables"""
    issues = []

    critical_env_vars = [
        "SECRET_KEY",
        "JWT_SECRET_KEY",
        "ENCRYPTION_KEY",
    ]

    for var in critical_env_vars:
        if not os.environ.get(var):
            issues.append(f"Missing critical environment variable: {var}")

    return issues


def check_log_configuration() -> List[str]:
    """Check logging configuration for security"""
    issues = []

    # Check if logs directory exists and has proper permissions
    if os.path.exists("logs/"):
        stat = os.stat("logs/")
        mode = oct(stat.st_mode)[-3:]
        if mode == "777":
            issues.append("Logs directory has overly permissive permissions (777)")

    # Check for log files that might contain sensitive data
    log_patterns = ["*.log", "logs/*.log", "output/*.log"]
    for pattern in log_patterns:
        import glob

        for log_file in glob.glob(pattern):
            if os.path.getsize(log_file) > 50 * 1024 * 1024:  # 50MB
                issues.append(
                    f"Large log file detected: {log_file} - may contain sensitive data"
                )

    return issues


def run_security_audit() -> Dict[str, List[str]]:
    """Run comprehensive security audit"""
    print("🔒 Running Security Audit for Passive OSINT Suite...")

    audit_results = {
        "file_permissions": check_file_permissions(),
        "hardcoded_secrets": scan_for_hardcoded_secrets(),
        "dependencies": check_dependencies(),
        "docker_security": check_docker_security(),
        "cors_configuration": check_cors_configuration(),
        "environment_variables": check_environment_variables(),
        "log_configuration": check_log_configuration(),
    }

    return audit_results


def print_audit_report(results: Dict[str, List[str]]) -> None:
    """Print formatted audit report"""
    total_issues = sum(len(issues) for issues in results.values())

    print(f"\n📊 Security Audit Results - {total_issues} issues found\n")
    print("=" * 60)

    for category, issues in results.items():
        status = "✅ PASS" if not issues else f"❌ FAIL ({len(issues)} issues)"
        print(f"\n{category.replace('_', ' ').title()}: {status}")

        if issues:
            for issue in issues:
                print(f"  • {issue}")

    print("\n" + "=" * 60)

    if total_issues == 0:
        print("🎉 No security issues detected!")
    else:
        print(f"⚠️  {total_issues} security issues require attention")
        print("\nRecommendations:")
        print("• Review and fix hardcoded secrets")
        print("• Update vulnerable dependencies")
        print("• Set proper file permissions (600 for sensitive files)")
        print("• Configure environment variables properly")
        print("• Review Docker security settings")


def generate_security_recommendations() -> List[str]:
    """Generate security hardening recommendations"""
    return [
        "🔐 Security Hardening Checklist:",
        "",
        "1. Environment Security:",
        "   • Copy .env.example to .env and fill with real values",
        "   • Set chmod 600 on .env and config/config.ini",
        "   • Use strong, unique passwords (32+ characters)",
        "   • Enable 2FA on all external service accounts",
        "",
        "2. API Security:",
        "   • Rotate API keys regularly (every 90 days)",
        "   • Use least-privilege access for API keys",
        "   • Monitor API usage for anomalies",
        "   • Implement rate limiting in production",
        "",
        "3. Infrastructure Security:",
        "   • Run containers as non-root users",
        "   • Use secrets management (e.g., Docker secrets, Kubernetes secrets)",
        "   • Enable container security scanning",
        "   • Implement network segmentation",
        "",
        "4. Operational Security:",
        "   • Enable audit logging",
        "   • Monitor for failed authentication attempts",
        "   • Implement intrusion detection",
        "   • Regular security updates and patching",
        "",
        "5. Data Protection:",
        "   • Encrypt sensitive data at rest",
        "   • Use TLS for all network communications",
        "   • Implement data retention policies",
        "   • Regular backup and recovery testing",
    ]


def main():
    """Main security audit function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--recommendations":
        recommendations = generate_security_recommendations()
        for rec in recommendations:
            print(rec)
        return

    results = run_security_audit()
    print_audit_report(results)

    print("\n" + "=" * 60)
    print("Run with --recommendations for detailed security hardening guide")


if __name__ == "__main__":
    main()
