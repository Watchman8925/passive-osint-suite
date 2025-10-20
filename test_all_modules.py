#!/usr/bin/env python3
"""
Comprehensive Module Testing Suite
Tests all OSINT modules for basic functionality
"""

import sys
import os
import json
from typing import Dict, Any
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Color codes for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


class ModuleTester:
    """Test all OSINT modules for basic functionality"""

    def __init__(self):
        self.results = {}
        self.total_modules = 0
        self.passed_modules = 0
        self.failed_modules = 0

    def print_header(self, text: str):
        """Print formatted header"""
        print(f"\n{BLUE}{'=' * 60}{RESET}")
        print(f"{BLUE}{text.center(60)}{RESET}")
        print(f"{BLUE}{'=' * 60}{RESET}\n")

    def print_success(self, text: str):
        """Print success message"""
        print(f"{GREEN}✓ {text}{RESET}")

    def print_error(self, text: str):
        """Print error message"""
        print(f"{RED}✗ {text}{RESET}")

    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{YELLOW}⚠ {text}{RESET}")

    def test_module_import(self, module_name: str, class_name: str) -> bool:
        """Test if a module can be imported"""
        try:
            module = __import__(f"modules.{module_name}", fromlist=[class_name])
            getattr(module, class_name)
            return True
        except ImportError as e:
            self.print_error(f"Import failed for {module_name}: {e}")
            return False
        except AttributeError as e:
            self.print_error(f"Class {class_name} not found in {module_name}: {e}")
            return False
        except Exception as e:
            self.print_error(f"Unexpected error loading {module_name}: {e}")
            return False

    def test_module_instantiation(self, module_name: str, class_name: str) -> Any:
        """Test if a module can be instantiated"""
        try:
            module = __import__(f"modules.{module_name}", fromlist=[class_name])
            cls = getattr(module, class_name)

            # Try to instantiate - some modules may need utils
            try:
                from utils.osint_utils import OSINTUtils

                utils = OSINTUtils()
                instance = cls(utils)
            except TypeError:
                # Try without utils
                instance = cls()

            return instance
        except ImportError as e:
            self.print_error(f"Import failed for {module_name}: {e}")
            return None
        except AttributeError as e:
            self.print_error(f"Class {class_name} not found in {module_name}: {e}")
            return None
        except TypeError as e:
            self.print_error(
                f"Type error instantiating {class_name} in {module_name}: {e}"
            )
            return None
        except Exception as e:
            self.print_error(
                f"Unexpected error instantiating {class_name} in {module_name}: {e}"
            )
            return None

    def test_module_methods(self, instance: Any, module_name: str) -> Dict[str, bool]:
        """Test if required methods exist"""
        results = {}

        # Common methods to check
        common_methods = [
            "search",
            "analyze",
            "enumerate",
            "scrape",
            "fetch",
            "get_history",
        ]

        for method in common_methods:
            if hasattr(instance, method):
                results[method] = True

        return results

    def test_module_registry(self) -> bool:
        """Test if MODULE_REGISTRY is working"""
        try:
            from modules import MODULE_REGISTRY

            self.print_success(
                f"MODULE_REGISTRY loaded with {len(MODULE_REGISTRY)} modules"
            )
            return True
        except Exception as e:
            self.print_error(f"MODULE_REGISTRY failed to load: {e}")
            return False

    def run_all_tests(self):
        """Run comprehensive module tests"""
        self.print_header("OSINT Suite - Module Test Suite")

        # Test 1: Module Registry
        print(f"\n{BLUE}Test 1: Module Registry{RESET}")
        registry_ok = self.test_module_registry()

        if not registry_ok:
            self.print_warning("Continuing with manual module testing...")

        # Define modules to test
        modules_to_test = [
            ("domain_recon", "DomainRecon"),
            ("email_intel", "EmailIntel"),
            ("ip_intel", "IPIntel"),
            ("social_media_footprint", "SocialMediaFootprint"),
            ("dark_web_intel", "DarkWebIntel"),
            ("company_intel", "CompanyIntel"),
            ("crypto_intel", "CryptoIntel"),
            ("breach_search", "BreachSearch"),
            ("github_search", "GitHubSearch"),
            ("certificate_transparency", "CertificateTransparency"),
            ("wayback_machine", "WaybackMachine"),
            ("search_engine_dorking", "SearchEngineDorking"),
            ("whois_history", "WhoisHistory"),
            ("paste_site_monitor", "PasteSiteMonitor"),
            ("threat_intel", "ThreatIntel"),
            ("malware_intel", "MalwareIntel"),
            ("subdomain_enum", "SubdomainEnum"),
            ("dns_intel", "DNSIntel"),
            ("iot_intel", "IoTIntel"),
            ("geospatial_intel", "GeospatialIntel"),
            ("flight_intel", "FlightIntel"),
            ("financial_intel", "FinancialIntel"),
            ("document_intel", "DocumentIntel"),
            ("digital_forensics", "DigitalForensics"),
            ("web_discovery", "WebDiscovery"),
            ("network_analysis", "NetworkAnalysis"),
            ("metadata_extractor", "MetadataExtractor"),
            ("code_analysis", "CodeAnalysis"),
            ("pattern_matching", "PatternMatching"),
        ]

        # Test 2: Module Imports
        print(f"\n{BLUE}Test 2: Module Imports{RESET}")
        for module_name, class_name in modules_to_test:
            self.total_modules += 1
            if self.test_module_import(module_name, class_name):
                self.print_success(f"{module_name} ({class_name})")
                self.results[module_name] = {
                    "import": True,
                    "instantiate": False,
                    "methods": {},
                }
                self.passed_modules += 1
            else:
                self.results[module_name] = {
                    "import": False,
                    "instantiate": False,
                    "methods": {},
                }
                self.failed_modules += 1

        # Test 3: Module Instantiation
        print(f"\n{BLUE}Test 3: Module Instantiation{RESET}")
        for module_name, class_name in modules_to_test:
            if self.results[module_name]["import"]:
                instance = self.test_module_instantiation(module_name, class_name)
                if instance:
                    self.print_success(f"{module_name} instantiated")
                    self.results[module_name]["instantiate"] = True

                    # Test methods
                    methods = self.test_module_methods(instance, module_name)
                    if methods:
                        self.results[module_name]["methods"] = methods
                        self.print_success(
                            f"{module_name} has methods: {', '.join(methods.keys())}"
                        )

        # Generate Report
        self.generate_report()

    def generate_report(self):
        """Generate test report"""
        self.print_header("Test Results Summary")

        print(f"Total Modules Tested: {self.total_modules}")
        print(f"{GREEN}Passed: {self.passed_modules}{RESET}")
        print(f"{RED}Failed: {self.failed_modules}{RESET}")

        success_rate = (
            (self.passed_modules / self.total_modules * 100)
            if self.total_modules > 0
            else 0
        )
        print(f"\nSuccess Rate: {success_rate:.1f}%")

        # Detailed results
        print(f"\n{BLUE}Detailed Results:{RESET}")
        for module_name, result in sorted(self.results.items()):
            status = "✓" if result["import"] else "✗"
            instantiate = "✓" if result["instantiate"] else "✗"
            methods_count = len(result["methods"])

            print(
                f"  {status} {module_name:<30} | Instantiate: {instantiate} | Methods: {methods_count}"
            )

        # Save results to file
        report_file = (
            f"module_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        try:
            with open(report_file, "w") as f:
                json.dump(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "total_modules": self.total_modules,
                        "passed": self.passed_modules,
                        "failed": self.failed_modules,
                        "success_rate": success_rate,
                        "results": self.results,
                    },
                    f,
                    indent=2,
                )
            self.print_success(f"Report saved to: {report_file}")
        except Exception as e:
            self.print_error(f"Failed to save report: {e}")

        # Return exit code based on results
        if self.failed_modules == 0:
            self.print_success("All module tests passed!")
            return 0
        else:
            self.print_warning(f"{self.failed_modules} module(s) failed tests")
            return 1


def main():
    """Main test runner"""
    tester = ModuleTester()
    exit_code = tester.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
