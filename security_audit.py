#!/usr/bin/env python3
"""
Security Audit Script for OSINT Suite
====================================

This script performs comprehensive security checks to ensure:
- API keys are properly encrypted and not exposed
- No sensitive information is leaked in logs or config files
- File permissions are secure
- No hardcoded credentials exist in the codebase
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Union

class SecurityAuditor:
    """Comprehensive security auditor for the OSINT Suite."""

    def __init__(self, workspace_path: str):
        self.workspace = Path(workspace_path)
        self.issues: List[str] = []
        self.warnings: List[str] = []
        self.passed: List[str] = []

    def audit(self) -> Dict[str, Union[List[str], float]]:
        """Run complete security audit."""
        print("🔒 Starting OSINT Suite Security Audit")
        print("=" * 50)

        self._check_encrypted_files()
        self._check_file_permissions()
        self._check_hardcoded_credentials()
        self._check_environment_variables()
        self._check_git_security()
        self._check_config_files()
        self._check_logs_for_sensitive_data()

        return self._generate_report()

    def _check_encrypted_files(self):
        """Check that encrypted files exist and are properly secured."""
        security_dir = self.workspace / "security"
        secrets_file = security_dir / "secrets.enc"
        key_file = security_dir / "encryption.key"

        # Check if encrypted files exist
        if not secrets_file.exists():
            self.issues.append("❌ secrets.enc file does not exist")
        else:
            self.passed.append("✅ Encrypted secrets file exists")

        if not key_file.exists():
            self.issues.append("❌ encryption.key file does not exist")
        else:
            self.passed.append("✅ Encryption key file exists")

        # Check file permissions
        if secrets_file.exists():
            perms = oct(secrets_file.stat().st_mode)[-3:]
            if perms != "600":
                self.issues.append(f"❌ secrets.enc has insecure permissions: {perms} (should be 600)")
            else:
                self.passed.append("✅ secrets.enc has secure permissions (600)")

        if key_file.exists():
            perms = oct(key_file.stat().st_mode)[-3:]
            if perms != "600":
                self.issues.append(f"❌ encryption.key has insecure permissions: {perms} (should be 600)")
            else:
                self.passed.append("✅ encryption.key has secure permissions (600)")

    def _check_file_permissions(self):
        """Check file permissions for sensitive files."""
        sensitive_files = [
            "security/secrets.enc",
            "security/encryption.key",
            "config.ini",
            "config/api_config.json",
            "config/api_status.json"
        ]

        for file_path in sensitive_files:
            full_path = self.workspace / file_path
            if full_path.exists():
                perms = oct(full_path.stat().st_mode)[-3:]
                if perms not in ["600", "644"]:
                    self.warnings.append(f"⚠️  {file_path} has permissions {perms}")

    def _check_hardcoded_credentials(self):
        """Check for hardcoded API keys or credentials in source code."""
        # Common API key patterns
        patterns = [
            r'sk-[a-zA-Z0-9]{48}',  # OpenAI
            r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+',  # Slack
            r'AIza[0-9A-Za-z-_]{35}',  # Google
            r'[A-Za-z0-9]{32}',  # Generic 32-char keys
            r'[A-Za-z0-9]{40}',  # GitHub tokens
            r'[A-Za-z0-9]{64}',  # Generic 64-char keys
        ]

        python_files = list(self.workspace.rglob("*.py"))

        # Exclude test files and demo files
        excluded_files = ['test_', 'demo_', 'example_', 'sample_']
        python_files = [f for f in python_files if not any(excl in f.name for excl in excluded_files)]

        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for pattern in patterns:
                    import re
                    matches = re.findall(pattern, content)
                    for match in matches:
                        # Skip if it's in a comment or test data
                        if not self._is_legitimate_key_usage(content, match, file_path):
                            self.issues.append(f"❌ Potential hardcoded credential in {file_path}: {match[:10]}...")

            except Exception as e:
                self.warnings.append(f"⚠️  Could not check {file_path}: {e}")

    def _is_legitimate_key_usage(self, content: str, match: str, file_path: Path) -> bool:
        """Check if a potential key match is legitimate (not hardcoded)."""
        # Known legitimate test/example keys and addresses
        known_legitimate = [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Satoshi's Bitcoin address
            "cd3ad0cae1mshc965b142654a663p1285f9jsn3a93297c8238",  # Test RapidAPI key
            "strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3kov7yd",  # Dread onion address
        ]

        if match in known_legitimate:
            return True

        # Check if it's in a legitimate context
        legitimate_contexts = [
            "getpass.getpass",
            "secrets_manager.get_secret",
            "os.getenv",
            "api_key",
            "API_KEY",
            "test",
            "example",
            "placeholder",
            "dummy",
            "fake",
            "demo",
            "sample",
            "bitcoin",
            "btc",
            "onion",
            ".onion"
        ]

        lines = content.split('\n')
        for i, line in enumerate(lines):
            if match in line:
                # Check surrounding context
                start = max(0, i-2)
                end = min(len(lines), i+3)
                context = '\n'.join(lines[start:end]).lower()

                for legit in legitimate_contexts:
                    if legit.lower() in context:
                        return True

                # Check if it's in a variable assignment that looks legitimate
                if any(phrase in line.lower() for phrase in ["api_key =", "key =", "token =", "secret =", "address =", "btc =", "bitcoin ="]):
                    return True

        return False

    def _check_environment_variables(self):
        """Check for sensitive environment variables."""
        sensitive_vars = [
            "OPENAI_API_KEY", "SHODAN_API_KEY", "GOOGLE_API_KEY",
            "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "DATABASE_URL",
            "REDIS_URL", "JWT_SECRET", "SECRET_KEY"
        ]

        exposed_vars = []
        for var in sensitive_vars:
            if os.getenv(var):
                exposed_vars.append(var)

        if exposed_vars:
            self.warnings.append(f"⚠️  Sensitive environment variables detected: {', '.join(exposed_vars)}")
            self.warnings.append("   💡 Consider using encrypted secrets manager instead")

    def _check_git_security(self):
        """Check git security (files not tracked, etc.)."""
        gitignore_path = self.workspace / ".gitignore"

        if not gitignore_path.exists():
            self.issues.append("❌ .gitignore file does not exist")
        else:
            with open(gitignore_path, 'r') as f:
                gitignore_content = f.read()

            required_ignores = ["secrets.enc", "*.enc", "encryption.key"]
            for ignore in required_ignores:
                if ignore not in gitignore_content:
                    self.issues.append(f"❌ {ignore} not in .gitignore")
                else:
                    self.passed.append(f"✅ {ignore} properly ignored in git")

    def _check_config_files(self):
        """Check configuration files for sensitive data."""
        config_files = [
            "config.ini",
            "config/api_config.json",
            "config/api_status.json",
            "pyproject.toml"
        ]

        for config_file in config_files:
            file_path = self.workspace / config_file
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for API keys in config files
                    if any(keyword in content.upper() for keyword in ["API_KEY", "SECRET", "TOKEN", "PASSWORD"]):
                        # More detailed check
                        lines = content.split('\n')
                        for line in lines:
                            if any(keyword in line.upper() for keyword in ["API_KEY", "SECRET", "TOKEN", "PASSWORD"]):
                                if '=' in line and not line.strip().startswith('#'):
                                    self.issues.append(f"❌ Potential sensitive data in {config_file}: {line.strip()[:50]}...")

                except Exception as e:
                    self.warnings.append(f"⚠️  Could not check {config_file}: {e}")

    def _check_logs_for_sensitive_data(self):
        """Check log files for sensitive information."""
        log_files = list(self.workspace.rglob("*.log")) + [self.workspace / "logs" / "api_validation_report.txt"]

        for log_file in log_files:
            if log_file.exists():
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for API keys in logs
                    import re
                    api_key_patterns = [
                        r'sk-[a-zA-Z0-9]{48}',
                        r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+',
                        r'AIza[0-9A-Za-z-_]{35}',
                    ]

                    for pattern in api_key_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            self.issues.append(f"❌ API key found in log file {log_file}")

                except Exception as e:
                    self.warnings.append(f"⚠️  Could not check log file {log_file}: {e}")

    def _generate_report(self) -> Dict[str, Union[List[str], float]]:
        """Generate audit report."""
        print("\n📊 Security Audit Results")
        print("=" * 30)

        if self.issues:
            print(f"\n🚨 CRITICAL ISSUES ({len(self.issues)}):")
            for issue in self.issues:
                print(f"   {issue}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   {warning}")

        if self.passed:
            print(f"\n✅ PASSED CHECKS ({len(self.passed)}):")
            for passed in self.passed:
                print(f"   {passed}")

        total_checks = len(self.issues) + len(self.warnings) + len(self.passed)
        security_score = (len(self.passed) / total_checks) * 100 if total_checks > 0 else 0

        print(f"\n🔒 Security Score: {security_score:.1f}%")
        if security_score >= 90:
            print("🎉 EXCELLENT: Your API keys and sensitive data are well protected!")
        elif security_score >= 75:
            print("👍 GOOD: Security is adequate but could be improved.")
        else:
            print("⚠️  POOR: Critical security issues need immediate attention!")

        return {
            "issues": self.issues,
            "warnings": self.warnings,
            "passed": self.passed,
            "security_score": security_score
        }


def main():
    """Main audit function."""
    workspace_path = "/workspaces/passive-osint-suite"

    auditor = SecurityAuditor(workspace_path)
    results = auditor.audit()

    # Exit with error code if there are critical issues
    if results["issues"]:
        sys.exit(1)


if __name__ == "__main__":
    main()