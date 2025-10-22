#!/usr/bin/env python3
"""OSINT Suite Health Check System."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import importlib

# Ensure the repository root is importable when the script is invoked directly.
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


LOGGER = logging.getLogger("health_check")


def _ensure_logger_configured(level: int = logging.INFO) -> None:
    """Configure a simple console logger for the health check script."""

    if LOGGER.handlers:
        LOGGER.setLevel(level)
        return

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(level)


def generate_api_token(
    secret: str,
    *,
    subject: str = "health-check",
    ttl_seconds: int = 600,
) -> str:
    """Generate a short-lived JWT for accessing protected health endpoints."""

    try:
        import jwt
    except (
        ImportError
    ) as exc:  # pragma: no cover - exercised in environments missing jwt
        raise RuntimeError(
            "PyJWT is required to generate health-check tokens. Install pyjwt and retry."
        ) from exc

    issued_at = int(time.time())
    payload = {
        "sub": subject,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    if isinstance(token, bytes):
        return token.decode("utf-8")
    return token


def run_api_health_check(
    url: str,
    token: str,
    *,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Call the API health endpoint with the provided bearer token."""

    import requests

    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


class HealthChecker:
    """Comprehensive health check system for OSINT Suite"""

    def __init__(self):
        self.results = {
            "timestamp": time.time(),
            "overall_status": "unknown",
            "checks": {},
            "recommendations": [],
        }

    def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        print("🔍 Running comprehensive health checks...\n")

        checks = [
            self.check_python_environment,
            self.check_core_dependencies,
            self.check_security_modules,
            self.check_network_modules,
            self.check_ai_modules,
            self.check_web_interface,
            self.check_configuration,
            self.check_file_permissions,
            self.check_external_services,
            self.check_system_resources,
        ]

        for check in checks:
            try:
                check()
            except Exception as e:
                self._add_check_result(check.__name__, "error", f"Check failed: {e}")

        self._determine_overall_status()
        self._generate_recommendations()

        return self.results

    def check_python_environment(self):
        """Check Python environment and version"""
        print("🐍 Checking Python environment...")

        # Python version
        version = sys.version_info
        python_version = f"{version.major}.{version.minor}.{version.micro}"

        if version.major >= 3 and version.minor >= 8:
            self._add_check_result("python_version", "pass", f"Python {python_version}")
        else:
            self._add_check_result(
                "python_version", "fail", f"Python {python_version} - requires 3.8+"
            )

        # Virtual environment
        in_venv = hasattr(sys, "real_prefix") or (
            hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
        )
        if in_venv:
            self._add_check_result(
                "virtual_environment", "pass", "Running in virtual environment"
            )
        else:
            self._add_check_result(
                "virtual_environment", "warning", "Not running in virtual environment"
            )

        # Required modules
        required_modules = [
            "requests",
            "beautifulsoup4",
            "cryptography",
            "pathlib",
            "json",
        ]

        for module in required_modules:
            try:
                importlib.import_module(module)
                self._add_check_result(
                    f"module_{module}", "pass", f"{module} available"
                )
            except ImportError:
                self._add_check_result(
                    f"module_{module}", "fail", f"{module} not available"
                )

    def check_core_dependencies(self):
        """Check core OSINT dependencies"""
        print("📦 Checking core dependencies...")

        core_modules = [
            ("dns.resolver", "DNS resolution"),
            ("urllib.parse", "URL parsing"),
            ("ssl", "SSL/TLS support"),
            ("socket", "Network sockets"),
            ("json", "JSON processing"),
            ("csv", "CSV processing"),
            ("datetime", "Date/time handling"),
            ("re", "Regular expressions"),
            ("hashlib", "Hashing functions"),
            ("base64", "Base64 encoding"),
        ]

        for module, description in core_modules:
            try:
                importlib.import_module(module)
                self._add_check_result(
                    f"core_{module.replace('.', '_')}", "pass", description
                )
            except ImportError:
                self._add_check_result(
                    f"core_{module.replace('.', '_')}",
                    "fail",
                    f"{description} unavailable",
                )

    def check_security_modules(self):
        """Check security and encryption modules"""
        print("🔒 Checking security modules...")

        security_modules = [
            ("cryptography.hazmat.primitives.asymmetric.ed25519", "ED25519 signatures"),
            ("cryptography.hazmat.primitives.ciphers.aead", "AES-GCM encryption"),
            ("secrets", "Cryptographically secure random"),
            ("bcrypt", "Password hashing"),
            ("keyring", "Secure credential storage"),
        ]

        for module, description in security_modules:
            try:
                importlib.import_module(module)
                self._add_check_result(
                    f"security_{module.split('.')[-1]}", "pass", description
                )
            except ImportError:
                self._add_check_result(
                    f"security_{module.split('.')[-1]}",
                    "warning",
                    f"{description} unavailable",
                )

        # Check local security modules
        local_security = [
            ("secrets_manager", "API key management"),
            ("result_encryption", "Result encryption"),
            ("audit_trail", "Audit logging"),
            ("opsec_policy", "OPSEC policy enforcement"),
        ]

        for module, description in local_security:
            try:
                importlib.import_module(f"security.{module}")
                self._add_check_result(f"local_security_{module}", "pass", description)
            except ImportError:
                self._add_check_result(
                    f"local_security_{module}", "fail", f"{description} unavailable"
                )

    def check_network_modules(self):
        """Check network and anonymity modules"""
        print("🌐 Checking network modules...")

        network_modules = [
            ("transport", "Network transport layer"),
            ("doh_client", "DNS over HTTPS"),
            ("anonymity_grid", "Anonymity grid system"),
        ]

        for module, description in network_modules:
            try:
                if module == "transport":
                    importlib.import_module(module)
                else:
                    importlib.import_module(f"utils.{module}")
                self._add_check_result(f"network_{module}", "pass", description)
            except ImportError:
                self._add_check_result(
                    f"network_{module}", "warning", f"{description} unavailable"
                )

        # Check Tor availability
        try:
            result = subprocess.run(["which", "tor"], capture_output=True, text=True)
            if result.returncode == 0:
                self._add_check_result("tor_available", "pass", "Tor is installed")
            else:
                self._add_check_result("tor_available", "warning", "Tor not found")
        except Exception:
            self._add_check_result(
                "tor_available", "warning", "Cannot check Tor availability"
            )

    def check_ai_modules(self):
        """Check AI and ML modules"""
        print("🤖 Checking AI modules...")

        ai_modules = [
            ("local_llm_engine", "Local LLM processing"),
            ("blackbox_patterns", "Pattern analysis"),
            ("cross_reference_engine", "Cross-reference engine"),
            ("conspiracy_analyzer", "Conspiracy analysis"),
            ("hidden_pattern_detector", "Pattern detection"),
        ]

        for module, description in ai_modules:
            found = False
            # Try multiple import paths for resilience
            for prefix in ["modules", "core", ""]:
                try:
                    if prefix:
                        importlib.import_module(f"{prefix}.{module}")
                    else:
                        importlib.import_module(module)
                    self._add_check_result(f"ai_{module}", "pass", description)
                    found = True
                    break
                except ImportError:
                    continue

            if not found:
                self._add_check_result(
                    f"ai_{module}", "warning", f"{description} unavailable"
                )

        # Check ML dependencies
        ml_deps = [
            ("torch", "PyTorch"),
            ("transformers", "Hugging Face Transformers"),
            ("sklearn", "Scikit-learn"),
        ]

        for module, description in ml_deps:
            try:
                importlib.import_module(module)
                self._add_check_result(
                    f"ml_{module}", "pass", f"{description} available"
                )
            except ImportError:
                self._add_check_result(
                    f"ml_{module}", "warning", f"{description} not available"
                )

    def check_web_interface(self):
        """Check web interface components"""
        print("🌐 Checking web interface...")

        # Check if web directory exists
        web_dir = Path("web")
        if web_dir.exists():
            self._add_check_result("web_directory", "pass", "Web directory exists")

            # Check package.json
            package_json = web_dir / "package.json"
            if package_json.exists():
                self._add_check_result("web_package_json", "pass", "package.json found")

                # Check node_modules
                node_modules = web_dir / "node_modules"
                if node_modules.exists():
                    self._add_check_result(
                        "web_dependencies", "pass", "Node.js dependencies installed"
                    )
                else:
                    self._add_check_result(
                        "web_dependencies",
                        "warning",
                        "Node.js dependencies not installed",
                    )
            else:
                self._add_check_result(
                    "web_package_json", "fail", "package.json not found"
                )
        else:
            self._add_check_result(
                "web_directory", "warning", "Web directory not found"
            )

    def check_configuration(self):
        """Check configuration files"""
        print("⚙️ Checking configuration...")

        config_files = [
            ("config.ini", "Main configuration"),
            ("config.ini.template", "Configuration template"),
            ("pyproject.toml", "Python project configuration"),
            ("requirements.txt", "Python dependencies"),
            ("requirements_minimal.txt", "Minimal dependencies"),
        ]

        for filename, description in config_files:
            if Path(filename).exists():
                self._add_check_result(
                    f"config_{filename.replace('.', '_')}",
                    "pass",
                    f"{description} exists",
                )
            else:
                self._add_check_result(
                    f"config_{filename.replace('.', '_')}",
                    "warning",
                    f"{description} not found",
                )

    def check_file_permissions(self):
        """Check file permissions and directory structure"""
        print("📁 Checking file permissions...")

        required_dirs = [
            "logs",
            "output",
            "output/encrypted",
            "output/audit",
            "investigations",
            "templates",
            "security",
        ]

        for dirname in required_dirs:
            dir_path = Path(dirname)
            if dir_path.exists():
                # Check if writable
                try:
                    test_file = dir_path / ".write_test"
                    test_file.write_text("test")
                    test_file.unlink()
                    self._add_check_result(
                        f"dir_{dirname.replace('/', '_')}",
                        "pass",
                        f"{dirname} writable",
                    )
                except Exception:
                    self._add_check_result(
                        f"dir_{dirname.replace('/', '_')}",
                        "fail",
                        f"{dirname} not writable",
                    )
            else:
                self._add_check_result(
                    f"dir_{dirname.replace('/', '_')}",
                    "warning",
                    f"{dirname} does not exist",
                )

    def check_external_services(self):
        """Check external service availability"""
        print("🔗 Checking external services...")

        # Test basic internet connectivity
        try:
            import requests

            response = requests.get("https://httpbin.org/status/200", timeout=5)
            if response.status_code == 200:
                self._add_check_result(
                    "internet_connectivity", "pass", "Internet connectivity OK"
                )
            else:
                self._add_check_result(
                    "internet_connectivity", "warning", "Internet connectivity issues"
                )
        except Exception:
            self._add_check_result(
                "internet_connectivity", "fail", "No internet connectivity"
            )

        # Test DNS resolution
        try:
            import socket

            socket.gethostbyname("google.com")
            self._add_check_result("dns_resolution", "pass", "DNS resolution working")
        except Exception:
            self._add_check_result("dns_resolution", "fail", "DNS resolution failed")

    def check_system_resources(self):
        """Check system resources"""
        print("💻 Checking system resources...")

        try:
            import psutil

            # Memory
            memory = psutil.virtual_memory()
            memory_gb = memory.total / (1024**3)
            if memory_gb >= 4:
                self._add_check_result(
                    "system_memory", "pass", f"{memory_gb:.1f}GB RAM available"
                )
            else:
                self._add_check_result(
                    "system_memory",
                    "warning",
                    f"{memory_gb:.1f}GB RAM - recommend 4GB+",
                )

            # Disk space
            disk = psutil.disk_usage(".")
            disk_gb = disk.free / (1024**3)
            if disk_gb >= 5:
                self._add_check_result(
                    "disk_space", "pass", f"{disk_gb:.1f}GB free disk space"
                )
            else:
                self._add_check_result(
                    "disk_space", "warning", f"{disk_gb:.1f}GB free - recommend 5GB+"
                )

        except ImportError:
            self._add_check_result(
                "system_resources",
                "warning",
                "psutil not available for resource checks",
            )

    def _add_check_result(self, check_name: str, status: str, message: str):
        """Add a check result"""
        self.results["checks"][check_name] = {
            "status": status,
            "message": message,
            "timestamp": time.time(),
        }

    def _determine_overall_status(self):
        """Determine overall health status"""
        checks = self.results["checks"]
        statuses = [check["status"] for check in checks.values()]

        if "fail" in statuses:
            self.results["overall_status"] = "critical"
        elif "warning" in statuses:
            self.results["overall_status"] = "warning"
        else:
            self.results["overall_status"] = "healthy"

    def _generate_recommendations(self):
        """Generate recommendations based on check results"""
        recommendations = []

        checks = self.results["checks"]

        # Python environment issues
        if checks.get("python_version", {}).get("status") == "fail":
            recommendations.append("Upgrade Python to version 3.8 or higher")

        if checks.get("virtual_environment", {}).get("status") == "warning":
            recommendations.append("Consider running in a Python virtual environment")

        # Missing security modules
        security_fails = [
            k
            for k, v in checks.items()
            if k.startswith("local_security_") and v["status"] == "fail"
        ]
        if security_fails:
            recommendations.append(
                "Run the installer to set up missing security modules"
            )

        # Network issues
        if checks.get("tor_available", {}).get("status") == "warning":
            recommendations.append(
                "Install Tor for full anonymity features: sudo apt install tor"
            )

        # Web interface issues
        if checks.get("web_dependencies", {}).get("status") == "warning":
            recommendations.append("Install web dependencies: cd web && npm install")

        # Configuration issues
        config_warnings = [
            k
            for k, v in checks.items()
            if k.startswith("config_") and v["status"] == "warning"
        ]
        if config_warnings:
            recommendations.append(
                "Run the installer to create missing configuration files"
            )

        # Directory issues
        dir_fails = [
            k
            for k, v in checks.items()
            if k.startswith("dir_") and v["status"] in ["fail", "warning"]
        ]
        if dir_fails:
            recommendations.append("Run the installer to create required directories")

        # Resource issues
        if checks.get("system_memory", {}).get("status") == "warning":
            recommendations.append(
                "Consider upgrading system memory for better performance"
            )

        if checks.get("disk_space", {}).get("status") == "warning":
            recommendations.append("Free up disk space for optimal operation")

        self.results["recommendations"] = recommendations

    def print_report(self):
        """Print a formatted health report"""
        print("\n" + "=" * 60)
        print("🏥 OSINT SUITE HEALTH REPORT")
        print("=" * 60)

        # Overall status
        status = self.results["overall_status"]
        if status == "healthy":
            print("✅ Overall Status: HEALTHY")
        elif status == "warning":
            print("⚠️  Overall Status: WARNING")
        else:
            print("❌ Overall Status: CRITICAL ISSUES")

        print()

        # Check results by category
        categories = {
            "Python Environment": [
                k
                for k in self.results["checks"]
                if k.startswith(("python_", "virtual_", "module_"))
            ],
            "Core Dependencies": [
                k for k in self.results["checks"] if k.startswith("core_")
            ],
            "Security Modules": [
                k
                for k in self.results["checks"]
                if k.startswith(("security_", "local_security_"))
            ],
            "Network Modules": [
                k
                for k in self.results["checks"]
                if k.startswith("network_") or k in ["tor_available"]
            ],
            "AI/ML Modules": [
                k for k in self.results["checks"] if k.startswith(("ai_", "ml_"))
            ],
            "Web Interface": [
                k for k in self.results["checks"] if k.startswith("web_")
            ],
            "Configuration": [
                k for k in self.results["checks"] if k.startswith("config_")
            ],
            "File System": [k for k in self.results["checks"] if k.startswith("dir_")],
            "External Services": [
                k
                for k in self.results["checks"]
                if k in ["internet_connectivity", "dns_resolution"]
            ],
            "System Resources": [
                k
                for k in self.results["checks"]
                if k in ["system_memory", "disk_space", "system_resources"]
            ],
        }

        for category, check_keys in categories.items():
            if not check_keys:
                continue

            print(f"📋 {category}:")
            for key in check_keys:
                if key in self.results["checks"]:
                    check = self.results["checks"][key]
                    status_icon = {
                        "pass": "✅",
                        "warning": "⚠️ ",
                        "fail": "❌",
                        "error": "💥",
                    }.get(check["status"], "?")
                    print(f"  {status_icon} {check['message']}")
            print()

        # Recommendations
        if self.results["recommendations"]:
            print("💡 RECOMMENDATIONS:")
            for rec in self.results["recommendations"]:
                print(f"  • {rec}")
            print()

        print("=" * 60)

    def save_report(self, filename: str = "health_report.json"):
        """Save health report to file"""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"📄 Report saved to {filename}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments for the health check script."""

    parser = argparse.ArgumentParser(description="Run OSINT Suite health checks.")
    parser.add_argument(
        "--api-url",
        help="Optional API health endpoint to query (requires a bearer token).",
    )
    parser.add_argument(
        "--secret",
        help="Override the OSINT_SECRET_KEY environment variable when generating the token.",
    )
    parser.add_argument(
        "--token-ttl",
        type=int,
        default=600,
        help="Validity period for the generated health-check token in seconds (default: 600).",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds when calling the API health endpoint (default: 5.0).",
    )
    parser.add_argument(
        "--output",
        default="health_report.json",
        help="Where to save the JSON health report (default: health_report.json).",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Skip saving the JSON report to disk.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the formatted console report.",
    )
    return parser.parse_args(argv)


def _maybe_run_api_health_check(
    checker: "HealthChecker",
    *,
    api_url: str,
    secret: Optional[str],
    token_ttl: int,
    request_timeout: float,
) -> None:
    """Optionally execute the authenticated API health check."""

    if not secret:
        message = (
            "OSINT_SECRET_KEY not provided; skipping authenticated API health check."
        )
        LOGGER.warning(message)
        checker._add_check_result("api_health", "warning", message)
        checker._determine_overall_status()
        checker._generate_recommendations()
        return

    try:
        token = generate_api_token(
            secret, subject="health-check-cli", ttl_seconds=token_ttl
        )
        response = run_api_health_check(api_url, token, timeout=request_timeout)
    except Exception as exc:  # pragma: no cover - exercised in integration tests
        LOGGER.error("API health check failed for %s: %s", api_url, exc)
        checker._add_check_result("api_health", "fail", f"API check failed: {exc}")
    else:
        status_text = response.get("status", "unknown")
        checker._add_check_result(
            "api_health",
            "pass",
            f"API responded with status '{status_text}'",
        )
        checker.results["checks"]["api_health"]["details"] = response
        LOGGER.info("API health check succeeded for %s", api_url)

    checker._determine_overall_status()
    checker._generate_recommendations()


def _exit_code_from_status(results: Dict[str, Any]) -> int:
    """Translate the overall status into a process exit code."""

    status = results.get("overall_status")
    if status == "healthy":
        return 0
    if status == "warning":
        return 1
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    """Main health check function."""

    args = parse_args(argv)
    _ensure_logger_configured(logging.WARNING if args.quiet else logging.INFO)

    checker = HealthChecker()
    checker.run_all_checks()

    if args.api_url:
        secret = args.secret or os.environ.get("OSINT_SECRET_KEY")
        _maybe_run_api_health_check(
            checker,
            api_url=args.api_url,
            secret=secret,
            token_ttl=args.token_ttl,
            request_timeout=args.request_timeout,
        )

    if not args.quiet:
        checker.print_report()

    if not args.no_save:
        checker.save_report(args.output)

    return _exit_code_from_status(checker.results)


if __name__ == "__main__":
    sys.exit(main())
