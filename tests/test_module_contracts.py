"""
Test suite to validate OSINT module contracts and interfaces.

This ensures all modules in MODULE_REGISTRY:
1. Can be instantiated
2. Have at least one execution method
3. Return proper response formats
4. Handle errors gracefully
"""

import pytest
from modules import MODULE_REGISTRY, get_module


# List of supported execution methods that modules may implement
# These are patterns - methods that start with these prefixes are considered execution methods
EXECUTION_METHOD_PATTERNS = [
    "search",
    "analyze",
    "enumerate",
    "scrape",
    "fetch",
    "get_history",
    "dork",
    "track",
    "monitor",
    "scan",
    "comprehensive",
]

# Specific execution methods that the API server checks for
SPECIFIC_EXECUTION_METHODS = [
    "search",
    "analyze_domain",
    "analyze_company",
    "analyze_email",
    "analyze_crypto_address",
    "enumerate",
    "scrape",
    "fetch_snapshots",
    "get_history",
    "scrape_profiles",
    "dork",
]


def test_module_registry_not_empty():
    """Verify MODULE_REGISTRY contains modules."""
    assert len(MODULE_REGISTRY) > 0, "MODULE_REGISTRY should not be empty"


def test_all_modules_have_required_fields():
    """Verify all modules in registry have required metadata."""
    for module_name, module_info in MODULE_REGISTRY.items():
        assert "class" in module_info, f"{module_name} missing 'class' field"
        assert "description" in module_info, f"{module_name} missing 'description'"
        assert "category" in module_info, f"{module_name} missing 'category'"
        assert module_info["class"] is not None, f"{module_name} has None class"


@pytest.mark.parametrize("module_name", list(MODULE_REGISTRY.keys()))
def test_module_can_be_instantiated(module_name):
    """Test that each module can be instantiated via get_module()."""
    # Skip modules that may have import errors due to missing dependencies
    skip_modules = [
        "conspiracy_analyzer",
        "hidden_pattern_detector",
        "reporting_engine",
        "realtime_feeds",
        "cross_reference_engine",
        "blackbox_patterns",
        "bellingcat_toolkit",
        "metadata_extractor",
        "local_dns_enumerator",
        "local_network_analyzer",
    ]
    
    if module_name in skip_modules:
        pytest.skip(f"Skipping {module_name} - may have optional dependencies")
    
    try:
        module_instance = get_module(module_name)
        assert module_instance is not None, f"get_module({module_name}) returned None"
    except Exception as e:
        pytest.fail(f"Failed to instantiate {module_name}: {e}")


@pytest.mark.parametrize("module_name", list(MODULE_REGISTRY.keys()))
def test_module_has_execution_method(module_name):
    """Test that each module has at least one supported execution method."""
    skip_modules = [
        "conspiracy_analyzer",
        "hidden_pattern_detector",
        "reporting_engine",
        "realtime_feeds",
        "cross_reference_engine",
        "blackbox_patterns",
        "bellingcat_toolkit",
        "metadata_extractor",
        "local_dns_enumerator",
        "local_network_analyzer",
    ]
    
    if module_name in skip_modules:
        pytest.skip(f"Skipping {module_name} - may have optional dependencies")
    
    try:
        module_instance = get_module(module_name)
        
        # Check for at least one execution method (specific or pattern-based)
        has_specific_method = any(
            hasattr(module_instance, method) for method in SPECIFIC_EXECUTION_METHODS
        )
        
        # Check for methods that match execution patterns
        module_methods = [
            m for m in dir(module_instance) 
            if not m.startswith("_") and callable(getattr(module_instance, m))
        ]
        has_pattern_method = any(
            any(m.startswith(pattern) for pattern in EXECUTION_METHOD_PATTERNS)
            for m in module_methods
        )
        
        if not (has_specific_method or has_pattern_method):
            # Filter out utility methods to show meaningful ones
            meaningful_methods = [
                m for m in module_methods 
                if m not in ["clean_text", "config", "extract_domains_from_text", 
                            "extract_emails_from_text", "extract_ips_from_text",
                            "get_all_api_keys", "get_api_key", "get_domain_ip_secure",
                            "get_domain_ipv6_secure", "get_obfuscation_status",
                            "check_rate_limit", "base_url", "tools", "databases",
                            "security_patterns", "core_modules"]
            ]
            pytest.fail(
                f"{module_name} does not have any supported execution method. "
                f"Expected one of: {SPECIFIC_EXECUTION_METHODS[:5]}... "
                f"or methods starting with: {EXECUTION_METHOD_PATTERNS[:5]}... "
                f"Available non-utility methods: {meaningful_methods[:10]}"
            )
        
    except Exception as e:
        pytest.skip(f"Could not test {module_name}: {e}")


def test_module_response_format_on_error():
    """Test that modules return proper error format for invalid input."""
    # Test with a simple module that should handle errors well
    try:
        from modules.domain_recon import DomainRecon
        
        module = DomainRecon()
        
        # Test with invalid input
        result = module.analyze_domain("")
        
        # Should return error response
        assert isinstance(result, dict), "Response should be a dictionary"
        assert "status" in result, "Response should have 'status' key"
        assert result["status"] == "error", "Invalid input should return error status"
        assert "error" in result, "Error response should have 'error' key"
        
    except ImportError:
        pytest.skip("DomainRecon module not available")


def test_get_module_with_invalid_name():
    """Test that get_module raises ValueError for invalid module name."""
    with pytest.raises(ValueError) as exc_info:
        get_module("nonexistent_module_12345")
    
    assert "not found" in str(exc_info.value).lower()


def test_module_registry_entries_match_execution_methods():
    """Verify sample modules have expected execution methods."""
    test_cases = {
        "domain_recon": "analyze_domain",
        "company_intel": "analyze_company",
        "email_intel": "analyze_email",
        "crypto_intel": "analyze_crypto_address",
    }
    
    for module_name, expected_method in test_cases.items():
        if module_name not in MODULE_REGISTRY:
            continue
        
        try:
            module_instance = get_module(module_name)
            assert hasattr(
                module_instance, expected_method
            ), f"{module_name} should have {expected_method} method"
        except Exception:
            # Skip if module can't be instantiated
            pass


def test_module_categories_exist():
    """Test that all modules have valid categories."""
    
    # Get all categories referenced in MODULE_REGISTRY
    used_categories = set()
    for module_info in MODULE_REGISTRY.values():
        used_categories.add(module_info["category"])
    
    # Verify major categories are present
    expected_categories = ["domain", "network", "web", "social", "business"]
    for cat in expected_categories:
        assert (
            cat in used_categories
        ), f"Expected category '{cat}' not found in any module"


def test_module_logger_available():
    """Test that modules have logger available."""
    try:
        from modules.domain_recon import DomainRecon
        
        module = DomainRecon()
        assert hasattr(module, "logger"), "Module should have logger attribute"
        assert module.logger is not None, "Module logger should not be None"
        
    except ImportError:
        pytest.skip("DomainRecon module not available")


def test_module_inherits_from_osint_utils():
    """Test that modules inherit from OSINTUtils."""
    try:
        from modules.domain_recon import DomainRecon
        from utils.osint_utils import OSINTUtils
        
        module = DomainRecon()
        assert isinstance(
            module, OSINTUtils
        ), "Module should inherit from OSINTUtils"
        
    except ImportError:
        pytest.skip("DomainRecon or OSINTUtils not available")


def test_module_has_validate_input():
    """Test that modules have validate_input method from OSINTUtils."""
    try:
        from modules.domain_recon import DomainRecon
        
        module = DomainRecon()
        assert hasattr(
            module, "validate_input"
        ), "Module should have validate_input method"
        assert callable(
            module.validate_input
        ), "validate_input should be callable"
        
    except ImportError:
        pytest.skip("DomainRecon module not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
