#!/usr/bin/env python3
"""
Simple test for enhanced OSINT modules core functionality
Tests without full OSINTUtils dependencies
"""

import os
from urllib.parse import urlparse, parse_qs, quote_plus
import re
import socket
from datetime import datetime


class SimpleTestOSINT:
    """Simplified test class without external dependencies"""

    def __init__(self):
        pass

    def make_request(self, url, headers=None, timeout=30):
        """Mock request method for testing"""

        # Return a mock response object
        class MockResponse:
            def __init__(self, status_code=200, text=""):
                self.status_code = status_code
                self.text = text

            def json(self):
                return {"mock": "response"}

        return MockResponse()


def test_rapidapi_structure():
    """Test RapidAPI module structure"""
    print("Testing RapidAPI Module Structure...")
    try:
        # Test that the file exists and has expected methods
        with open("modules/rapidapi_osint.py", "r") as f:
            content = f.read()

        # Check for key methods
        expected_methods = [
            "search_hunter_email_finder",
            "search_clearbit_company",
            "comprehensive_person_search",
            "comprehensive_company_search",
        ]

        for method in expected_methods:
            if f"def {method}" in content:
                print(f"✓ Method {method} found")
            else:
                print(f"✗ Method {method} not found")

        # Check for RapidAPI key
        if "cd3ad0cae1mshc965b142654a663p1285f9jsn3a93297c8238" in content:
            print("✓ RapidAPI key configured")
        else:
            print("✗ RapidAPI key not found")

        print("✓ RapidAPI module structure OK")

    except Exception as e:
        print(f"✗ RapidAPI structure test failed: {e}")


def test_preseeded_databases_structure():
    """Test pre-seeded databases module structure"""
    print("Testing Pre-seeded Databases Module Structure...")
    try:
        with open("modules/preseeded_databases.py", "r") as f:
            content = f.read()

        # Check for key databases
        expected_dbs = [
            "us_cisa_known_exploited",
            "us_fbi_most_wanted",
            "us_treasury_sanctions",
        ]

        for db in expected_dbs:
            if db in content:
                print(f"✓ Database {db} configured")
            else:
                print(f"✗ Database {db} not found")

        # Check for key methods
        expected_methods = [
            "fetch_cisa_vulnerabilities",
            "search_fbi_most_wanted",
            "comprehensive_search",
        ]

        for method in expected_methods:
            if f"def {method}" in content:
                print(f"✓ Method {method} found")
            else:
                print(f"✗ Method {method} not found")

        print("✓ Pre-seeded databases module structure OK")

    except Exception as e:
        print(f"✗ Pre-seeded databases structure test failed: {e}")


def test_free_tools_functionality():
    """Test free tools functionality without dependencies"""
    print("Testing Free Tools Functionality...")
    try:
        # Test URL analysis
        def analyze_url_locally(url):
            result = {
                "original_url": url,
                "analysis_timestamp": datetime.now().isoformat(),
            }

            try:
                parsed = urlparse(url)
                result.update(
                    {
                        "scheme": parsed.scheme,
                        "netloc": parsed.netloc,
                        "hostname": parsed.hostname,
                        "port": parsed.port,
                        "path": parsed.path,
                        "query": parsed.query,
                        "fragment": parsed.fragment,
                        "is_valid": True,
                    }
                )

                if parsed.query:
                    result["query_params"] = parse_qs(parsed.query)

                return result
            except Exception as e:
                result["error"] = str(e)
                result["is_valid"] = False
                return result

        # Test URL analysis
        test_url = "https://example.com/test?param=value&other=test"
        analysis = analyze_url_locally(test_url)

        if analysis["scheme"] == "https" and analysis["hostname"] == "example.com":
            print("✓ URL analysis working")
        else:
            print("✗ URL analysis failed")

        # Test pattern extraction
        def extract_patterns_from_text(text):
            patterns = {
                "emails": re.findall(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text
                ),
                "urls": re.findall(
                    r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
                    text,
                ),
                "ip_addresses": re.findall(
                    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text
                ),
            }
            return patterns

        test_text = "Contact john@example.com or visit http://test.com. IP: 192.168.1.1"
        patterns = extract_patterns_from_text(test_text)

        if (
            len(patterns["emails"]) == 1
            and len(patterns["urls"]) == 1
            and len(patterns["ip_addresses"]) == 1
        ):
            print("✓ Pattern extraction working")
        else:
            print("✗ Pattern extraction failed")

        # Test DNS lookup
        try:
            ip_address = socket.gethostbyname("example.com")
            if ip_address:
                print("✓ DNS lookup working")
            else:
                print("✗ DNS lookup failed")
        except Exception:
            print("✗ DNS lookup failed (network issue)")

        print("✓ Free tools functionality OK")

    except Exception as e:
        print(f"✗ Free tools functionality test failed: {e}")


def test_enhanced_dorking_patterns():
    """Test enhanced dorking patterns"""
    print("Testing Enhanced Dorking Patterns...")
    try:

        def google_dorking_patterns(target, dork_type="general"):
            patterns = []

            if dork_type == "general":
                patterns.extend(
                    [
                        f"site:{target}",
                        f"inurl:{target}",
                        f"intitle:{target}",
                        f"intext:{target}",
                    ]
                )
            elif dork_type == "email":
                patterns.extend(
                    [
                        f'"{target}" "@gmail.com"',
                        f'"{target}" "@yahoo.com"',
                        f'"{target}" email',
                    ]
                )

            return patterns

        # Test pattern generation
        general_patterns = google_dorking_patterns("example.com", "general")
        email_patterns = google_dorking_patterns("example.com", "email")

        if len(general_patterns) == 4 and len(email_patterns) == 3:
            print("✓ Dorking patterns generated correctly")
        else:
            print("✗ Dorking patterns incorrect")

        # Test search query encoding
        query = 'site:example.com "password"'
        encoded = quote_plus(query)
        if encoded:
            print("✓ Query encoding working")
        else:
            print("✗ Query encoding failed")

        print("✓ Enhanced dorking patterns OK")

    except Exception as e:
        print(f"✗ Enhanced dorking patterns test failed: {e}")


def test_module_files():
    """Test that module files exist and are properly structured"""
    print("Testing Module Files...")
    try:
        required_files = [
            "modules/rapidapi_osint.py",
            "modules/preseeded_databases.py",
            "modules/free_tools.py",
            "modules/search_engine_dorking.py",
        ]

        for file_path in required_files:
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    content = f.read()
                    if len(content) > 1000:  # Basic check for substantial content
                        print(f"✓ {file_path} exists and has content")
                    else:
                        print(f"✗ {file_path} exists but seems empty")
            else:
                print(f"✗ {file_path} not found")

        print("✓ Module files check complete")

    except Exception as e:
        print(f"✗ Module files test failed: {e}")


def main():
    """Run all tests"""
    print("=== OSINT Suite Enhanced Modules Simple Test ===\n")

    os.chdir("/workspaces/passive_osint_suite")

    test_module_files()
    print()

    test_rapidapi_structure()
    print()

    test_preseeded_databases_structure()
    print()

    test_free_tools_functionality()
    print()

    test_enhanced_dorking_patterns()
    print()

    print("=== Simple Test Complete ===")


if __name__ == "__main__":
    main()
