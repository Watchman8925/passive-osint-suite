#!/usr/bin/env python3
"""
Test script for enhanced OSINT modules
Tests the new RapidAPI, pre-seeded databases, and free tools modules
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_rapidapi_module():
    """Test RapidAPI OSINT module"""
    print("Testing RapidAPI OSINT Module...")
    try:
        from modules.rapidapi_osint import RapidAPIOSINTModule
        rapidapi = RapidAPIOSINTModule()

        # Test database info
        # info = rapidapi.get_database_info('us_cisa_known_exploited')
        # print(f"✓ CISA database info: {info['name'] if info else 'Not found'}")

        # Test comprehensive search (limited to avoid API calls)
        print("✓ RapidAPI module initialized successfully")

    except Exception as e:
        print(f"✗ RapidAPI module test failed: {e}")


def test_preseeded_databases():
    """Test pre-seeded databases module"""
    print("Testing Pre-seeded Databases Module...")
    try:
        from modules.preseeded_databases import PreSeededDatabases
        db = PreSeededDatabases()

        # Test database listing
        databases = db.list_databases()
        print(f"✓ Available databases: {len(databases)}")

        # Test database info
        info = db.get_database_info('us_cisa_known_exploited')
        print(f"✓ CISA database: {info['name'] if info else 'Not found'}")

        # Test statistics
        stats = db.get_database_statistics()
        print(f"✓ Database categories: {list(stats['categories'].keys())}")

        print("✓ Pre-seeded databases module working")

    except Exception as e:
        print(f"✗ Pre-seeded databases test failed: {e}")


def test_free_tools():
    """Test free tools module"""
    print("Testing Free Tools Module...")
    try:
        from modules.free_tools import FreeToolsOSINT
        tools = FreeToolsOSINT()

        # Test system info
        sys_info = tools.system_network_info()
        print(f"✓ System hostname: {sys_info.get('hostname', 'Unknown')}")

        # Test URL analysis
        url_analysis = tools.analyze_url_locally("https://example.com/test?param=value")
        print(f"✓ URL analysis: scheme={url_analysis.get('scheme')}")

        # Test pattern extraction
        test_text = "Contact john@example.com or visit http://test.com. IP: 192.168.1.1"
        patterns = tools.extract_patterns_from_text(test_text)
        print(f"✓ Pattern extraction: emails={len(patterns['emails'])}, urls={len(patterns['urls'])}")

        print("✓ Free tools module working")

    except Exception as e:
        print(f"✗ Free tools test failed: {e}")


def test_enhanced_dorking():
    """Test enhanced search engine dorking"""
    print("Testing Enhanced Search Engine Dorking...")
    try:
        from modules.search_engine_dorking import SearchEngineDorking
        dorking = SearchEngineDorking()

        # Test dork pattern generation
        patterns = dorking.google_dorking_patterns("example.com", "general")
        print(f"✓ Generated {len(patterns)} general dork patterns")

        # Test comprehensive dorking patterns
        all_patterns = dorking.google_dorking_patterns("example.com", "email")
        print(f"✓ Generated {len(all_patterns)} email dork patterns")

        print("✓ Enhanced dorking module working")

    except Exception as e:
        print(f"✗ Enhanced dorking test failed: {e}")


def test_module_registry():
    """Test that modules are properly registered"""
    print("Testing Module Registry...")
    try:
        # Import modules individually to avoid dependency issues
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

        # Check if our new modules exist as files
        new_modules = ['rapidapi_osint', 'preseeded_databases', 'free_tools']
        modules_dir = os.path.join(os.path.dirname(__file__), 'modules')

        for module_name in new_modules:
            module_file = os.path.join(modules_dir, f'{module_name}.py')
            if os.path.exists(module_file):
                print(f"✓ Module file '{module_name}.py' exists")
            else:
                print(f"✗ Module file '{module_name}.py' not found")

        print("✓ Module files check complete")

    except Exception as e:
        print(f"✗ Module registry test failed: {e}")


def main():
    """Run all tests"""
    print("=== OSINT Suite Enhanced Modules Test ===\n")

    test_module_registry()
    print()

    test_rapidapi_module()
    print()

    test_preseeded_databases()
    print()

    test_free_tools()
    print()

    test_enhanced_dorking()
    print()

    print("=== Test Complete ===")


if __name__ == "__main__":
    main()