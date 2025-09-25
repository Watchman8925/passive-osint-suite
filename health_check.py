#!/usr/bin/env python3
"""
OSINT Suite Health Check System
Comprehensive validation of all components and dependencies
"""

import sys
import os
import importlib
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import time

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class HealthChecker:
    """Comprehensive health check system for OSINT Suite"""

    def __init__(self):
        self.results = {
            "timestamp": time.time(),
            "overall_status": "unknown",
            "checks": {},
            "recommendations": []
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
            self.check_system_resources
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
            self._add_check_result("python_version", "fail", f"Python {python_version} - requires 3.8+")

        # Virtual environment
        in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        if in_venv:
            self._add_check_result("virtual_environment", "pass", "Running in virtual environment")
        else:
            self._add_check_result("virtual_environment", "warning", "Not running in virtual environment")

        # Required modules
        required_modules = [
            'requests', 'beautifulsoup4', 'cryptography', 'pathlib', 'json'
        ]

        for module in required_modules:
            try:
                importlib.import_module(module)
                self._add_check_result(f"module_{module}", "pass", f"{module} available")
            except ImportError:
                self._add_check_result(f"module_{module}", "fail", f"{module} not available")

    def check_core_dependencies(self):
        """Check core OSINT dependencies"""
        print("📦 Checking core dependencies...")

        core_modules = [
            ('dns.resolver', 'DNS resolution'),
            ('urllib.parse', 'URL parsing'),
            ('ssl', 'SSL/TLS support'),
            ('socket', 'Network sockets'),
            ('json', 'JSON processing'),
            ('csv', 'CSV processing'),
            ('datetime', 'Date/time handling'),
            ('re', 'Regular expressions'),
            ('hashlib', 'Hashing functions'),
            ('base64', 'Base64 encoding')
        ]

        for module, description in core_modules:
            try:
                importlib.import_module(module)
                self._add_check_result(f"core_{module.replace('.', '_')}", "pass", description)
            except ImportError:
                self._add_check_result(f"core_{module.replace('.', '_')}", "fail", f"{description} unavailable")

    def check_security_modules(self):
        """Check security and encryption modules"""
        print("🔒 Checking security modules...")

        security_modules = [
            ('cryptography.hazmat.primitives.asymmetric.ed25519', 'ED25519 signatures'),
            ('cryptography.hazmat.primitives.ciphers.aead', 'AES-GCM encryption'),
            ('secrets', 'Cryptographically secure random'),
            ('bcrypt', 'Password hashing'),
            ('keyring', 'Secure credential storage')
        ]

        for module, description in security_modules:
            try:
                importlib.import_module(module)
                self._add_check_result(f"security_{module.split('.')[-1]}", "pass", description)
            except ImportError:
                self._add_check_result(f"security_{module.split('.')[-1]}", "warning", f"{description} unavailable")

        # Check local security modules
        local_security = [
            ('secrets_manager', 'API key management'),
            ('result_encryption', 'Result encryption'),
            ('audit_trail', 'Audit logging'),
            ('opsec_policy', 'OPSEC policy enforcement')
        ]

        for module, description in local_security:
            try:
                importlib.import_module(f"security.{module}")
                self._add_check_result(f"local_security_{module}", "pass", description)
            except ImportError:
                self._add_check_result(f"local_security_{module}", "fail", f"{description} unavailable")

    def check_network_modules(self):
        """Check network and anonymity modules"""
        print("🌐 Checking network modules...")

        network_modules = [
            ('transport', 'Network transport layer'),
            ('doh_client', 'DNS over HTTPS'),
            ('anonymity_grid', 'Anonymity grid system')
        ]

        for module, description in network_modules:
            try:
                if module == 'transport':
                    importlib.import_module(module)
                else:
                    importlib.import_module(f"utils.{module}")
                self._add_check_result(f"network_{module}", "pass", description)
            except ImportError:
                self._add_check_result(f"network_{module}", "warning", f"{description} unavailable")

        # Check Tor availability
        try:
            result = subprocess.run(['which', 'tor'], capture_output=True, text=True)
            if result.returncode == 0:
                self._add_check_result("tor_available", "pass", "Tor is installed")
            else:
                self._add_check_result("tor_available", "warning", "Tor not found")
        except Exception:
            self._add_check_result("tor_available", "warning", "Cannot check Tor availability")

    def check_ai_modules(self):
        """Check AI and ML modules"""
        print("🤖 Checking AI modules...")

        ai_modules = [
            ('local_llm_engine', 'Local LLM processing'),
            ('blackbox_patterns', 'Pattern analysis'),
            ('cross_reference_engine', 'Cross-reference engine'),
            ('conspiracy_analyzer', 'Conspiracy analysis'),
            ('hidden_pattern_detector', 'Pattern detection')
        ]

        for module, description in ai_modules:
            try:
                importlib.import_module(f"modules.{module}")
                self._add_check_result(f"ai_{module}", "pass", description)
            except ImportError:
                self._add_check_result(f"ai_{module}", "warning", f"{description} unavailable")

        # Check ML dependencies
        ml_deps = [
            ('torch', 'PyTorch'),
            ('transformers', 'Hugging Face Transformers'),
            ('sklearn', 'Scikit-learn')
        ]

        for module, description in ml_deps:
            try:
                importlib.import_module(module)
                self._add_check_result(f"ml_{module}", "pass", f"{description} available")
            except ImportError:
                self._add_check_result(f"ml_{module}", "warning", f"{description} not available")

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
                    self._add_check_result("web_dependencies", "pass", "Node.js dependencies installed")
                else:
                    self._add_check_result("web_dependencies", "warning", "Node.js dependencies not installed")
            else:
                self._add_check_result("web_package_json", "fail", "package.json not found")
        else:
            self._add_check_result("web_directory", "warning", "Web directory not found")

    def check_configuration(self):
        """Check configuration files"""
        print("⚙️ Checking configuration...")

        config_files = [
            ('config.ini', 'Main configuration'),
            ('config.ini.template', 'Configuration template'),
            ('pyproject.toml', 'Python project configuration'),
            ('requirements.txt', 'Python dependencies'),
            ('requirements_minimal.txt', 'Minimal dependencies')
        ]

        for filename, description in config_files:
            if Path(filename).exists():
                self._add_check_result(f"config_{filename.replace('.', '_')}", "pass", f"{description} exists")
            else:
                self._add_check_result(f"config_{filename.replace('.', '_')}", "warning", f"{description} not found")

    def check_file_permissions(self):
        """Check file permissions and directory structure"""
        print("📁 Checking file permissions...")

        required_dirs = [
            'logs', 'output', 'output/encrypted', 'output/audit',
            'investigations', 'templates', 'security'
        ]

        for dirname in required_dirs:
            dir_path = Path(dirname)
            if dir_path.exists():
                # Check if writable
                try:
                    test_file = dir_path / '.write_test'
                    test_file.write_text('test')
                    test_file.unlink()
                    self._add_check_result(f"dir_{dirname.replace('/', '_')}", "pass", f"{dirname} writable")
                except Exception:
                    self._add_check_result(f"dir_{dirname.replace('/', '_')}", "fail", f"{dirname} not writable")
            else:
                self._add_check_result(f"dir_{dirname.replace('/', '_')}", "warning", f"{dirname} does not exist")

    def check_external_services(self):
        """Check external service availability"""
        print("🔗 Checking external services...")

        # Test basic internet connectivity
        try:
            import requests
            response = requests.get('https://httpbin.org/status/200', timeout=5)
            if response.status_code == 200:
                self._add_check_result("internet_connectivity", "pass", "Internet connectivity OK")
            else:
                self._add_check_result("internet_connectivity", "warning", "Internet connectivity issues")
        except Exception:
            self._add_check_result("internet_connectivity", "fail", "No internet connectivity")

        # Test DNS resolution
        try:
            import socket
            socket.gethostbyname('google.com')
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
                self._add_check_result("system_memory", "pass", f"{memory_gb:.1f}GB RAM available")
            else:
                self._add_check_result("system_memory", "warning", f"{memory_gb:.1f}GB RAM - recommend 4GB+")

            # Disk space
            disk = psutil.disk_usage('.')
            disk_gb = disk.free / (1024**3)
            if disk_gb >= 5:
                self._add_check_result("disk_space", "pass", f"{disk_gb:.1f}GB free disk space")
            else:
                self._add_check_result("disk_space", "warning", f"{disk_gb:.1f}GB free - recommend 5GB+")

        except ImportError:
            self._add_check_result("system_resources", "warning", "psutil not available for resource checks")

    def _add_check_result(self, check_name: str, status: str, message: str):
        """Add a check result"""
        self.results["checks"][check_name] = {
            "status": status,
            "message": message,
            "timestamp": time.time()
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
        security_fails = [k for k, v in checks.items() if k.startswith("local_security_") and v["status"] == "fail"]
        if security_fails:
            recommendations.append("Run the installer to set up missing security modules")

        # Network issues
        if checks.get("tor_available", {}).get("status") == "warning":
            recommendations.append("Install Tor for full anonymity features: sudo apt install tor")

        # Web interface issues
        if checks.get("web_dependencies", {}).get("status") == "warning":
            recommendations.append("Install web dependencies: cd web && npm install")

        # Configuration issues
        config_warnings = [k for k, v in checks.items() if k.startswith("config_") and v["status"] == "warning"]
        if config_warnings:
            recommendations.append("Run the installer to create missing configuration files")

        # Directory issues
        dir_fails = [k for k, v in checks.items() if k.startswith("dir_") and v["status"] in ["fail", "warning"]]
        if dir_fails:
            recommendations.append("Run the installer to create required directories")

        # Resource issues
        if checks.get("system_memory", {}).get("status") == "warning":
            recommendations.append("Consider upgrading system memory for better performance")

        if checks.get("disk_space", {}).get("status") == "warning":
            recommendations.append("Free up disk space for optimal operation")

        self.results["recommendations"] = recommendations

    def print_report(self):
        """Print a formatted health report"""
        print("\n" + "="*60)
        print("🏥 OSINT SUITE HEALTH REPORT")
        print("="*60)

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
            "Python Environment": [k for k in self.results["checks"] if k.startswith(("python_", "virtual_", "module_"))],
            "Core Dependencies": [k for k in self.results["checks"] if k.startswith("core_")],
            "Security Modules": [k for k in self.results["checks"] if k.startswith(("security_", "local_security_"))],
            "Network Modules": [k for k in self.results["checks"] if k.startswith("network_") or k in ["tor_available"]],
            "AI/ML Modules": [k for k in self.results["checks"] if k.startswith(("ai_", "ml_"))],
            "Web Interface": [k for k in self.results["checks"] if k.startswith("web_")],
            "Configuration": [k for k in self.results["checks"] if k.startswith("config_")],
            "File System": [k for k in self.results["checks"] if k.startswith("dir_")],
            "External Services": [k for k in self.results["checks"] if k in ["internet_connectivity", "dns_resolution"]],
            "System Resources": [k for k in self.results["checks"] if k in ["system_memory", "disk_space", "system_resources"]]
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
                        "error": "💥"
                    }.get(check["status"], "?")
                    print(f"  {status_icon} {check['message']}")
            print()

        # Recommendations
        if self.results["recommendations"]:
            print("💡 RECOMMENDATIONS:")
            for rec in self.results["recommendations"]:
                print(f"  • {rec}")
            print()

        print("="*60)

    def save_report(self, filename: str = "health_report.json"):
        """Save health report to file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"📄 Report saved to {filename}")


def main():
    """Main health check function"""
    checker = HealthChecker()
    results = checker.run_all_checks()
    checker.print_report()

    # Save detailed report
    checker.save_report()

    # Return appropriate exit code
    if results["overall_status"] == "healthy":
        return 0
    elif results["overall_status"] == "warning":
        return 1
    else:
        return 2


if __name__ == "__main__":
    sys.exit(main())