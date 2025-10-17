"""
Module Adapters - Add standard interface wrappers to existing modules

This module provides adapter methods that wrap existing module functionality
to conform to the MODULE_CAPABILITY_CONTRACT standard interface.
"""


def add_search_wrapper(module_class, primary_method_name):
    """
    Add a search() wrapper method to a module class

    Args:
        module_class: The module class to modify
        primary_method_name: Name of the primary method to wrap
    """

    def search(self, target, **kwargs):
        """Standard search interface - wraps primary module method"""
        try:
            primary_method = getattr(self, primary_method_name)
            result = primary_method(target, **kwargs)

            # If result is already in standard format, return as-is
            if isinstance(result, dict) and "status" in result:
                return result

            # Otherwise, wrap it
            return {"status": "success", "data": result}
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            return {"status": "error", "error": str(e)}

    # Add the method to the class
    search.__name__ = "search"
    search.__doc__ = f"Standard search interface - wraps {primary_method_name}()"
    setattr(module_class, "search", search)


def add_scrape_profiles_wrapper(module_class, primary_method_name):
    """Add a scrape_profiles() wrapper method"""

    def scrape_profiles(self, name_or_handle, **kwargs):
        """Standard scrape_profiles interface - wraps primary module method"""
        try:
            primary_method = getattr(self, primary_method_name)
            result = primary_method(name_or_handle, **kwargs)

            if isinstance(result, dict) and "status" in result:
                return result

            return {"status": "success", "data": result}
        except Exception as e:
            self.logger.error(f"Profile scraping failed: {e}")
            return {"status": "error", "error": str(e)}

    scrape_profiles.__name__ = "scrape_profiles"
    scrape_profiles.__doc__ = (
        f"Standard scrape_profiles interface - wraps {primary_method_name}()"
    )
    setattr(module_class, "scrape_profiles", scrape_profiles)


# Module-specific adapter mappings
# Format: module_name -> (wrapper_function, primary_method_name)
ADAPTER_MAPPINGS = {
    # Domain and network modules
    "domain_recon": (add_search_wrapper, "analyze_domain"),
    "ip_intel": (add_search_wrapper, "analyze_ip"),
    "dns_intelligence": (add_search_wrapper, "comprehensive_dns_analysis"),
    # Email and business
    "email_intel": (add_search_wrapper, "analyze_email"),
    # Social media
    "comprehensive_social_passive": (
        add_scrape_profiles_wrapper,
        "search_all_platforms",
    ),
    # Code repositories
    "gitlab_passive": (add_search_wrapper, "search_repositories"),
    "bitbucket_passive": (add_search_wrapper, "search_repositories"),
    "code_analysis": (add_search_wrapper, "comprehensive_repo_analysis"),
    # Academic and patents
    "academic_passive": (add_search_wrapper, "search_academic_sources"),
    # Intelligence gathering
    "crypto_intel": (add_search_wrapper, "analyze_crypto_address"),
    "darkweb_intel": (add_search_wrapper, "analyze_dark_web"),
    "document_intel": (add_search_wrapper, "analyze_document_leaks"),
    "financial_intel": (add_search_wrapper, "analyze_financial_entity"),
    "flight_intel": (add_search_wrapper, "analyze_aircraft"),
    "geospatial_intel": (add_search_wrapper, "analyze_location"),
    "iot_intel": (add_search_wrapper, "analyze_iot_devices"),
    "malware_intel": (add_search_wrapper, "analyze_file_hash"),
    # Analysis and tools
    "digital_forensics": (add_search_wrapper, "comprehensive_file_analysis"),
    "network_analysis": (add_search_wrapper, "analyze_pcap_file"),
    "web_discovery": (add_search_wrapper, "comprehensive_web_discovery"),
    "pattern_matching": (add_search_wrapper, "comprehensive_security_analysis"),
    "free_tools": (add_search_wrapper, "comprehensive_file_analysis"),
    # Specialized modules
    "preseeded_databases": (add_search_wrapper, "comprehensive_search"),
    "rapidapi_osint": (add_search_wrapper, "comprehensive_domain_search"),
    "passive_search": (add_search_wrapper, "analyze_target"),
    "paste_site_monitor": (add_search_wrapper, "search_pastes"),
    "patent_passive": (add_search_wrapper, "search_patent_databases"),
    "comprehensive_sweep": (add_search_wrapper, "comprehensive_sweep"),
    # Investigation tools
    "bellingcat_toolkit": (add_search_wrapper, "investigate_social_media"),
    "blackbox_patterns": (add_search_wrapper, "analyze_patterns"),
    "cross_reference_engine": (add_search_wrapper, "cross_reference_search"),
    # Reporting (not typical OSINT but needs interface for API compatibility)
    "reporting_engine": (add_search_wrapper, "generate_executive_summary"),
    # Local tools
    "local_dns_enumerator": (add_search_wrapper, "enumerate_domain"),
    "local_network_analyzer": (add_search_wrapper, "analyze_network"),
    "metadata_extractor": (add_search_wrapper, "extract_metadata"),
}


def apply_adapters(module_registry):
    """
    Apply adapter methods to all modules that need them

    Args:
        module_registry: The MODULE_REGISTRY dict
    """
    applied_count = 0

    for module_name, (wrapper_func, primary_method) in ADAPTER_MAPPINGS.items():
        if module_name not in module_registry:
            continue

        module_info = module_registry[module_name]
        module_class = module_info.get("class")

        if module_class is None:
            continue

        # Check if the primary method exists
        if not hasattr(module_class, primary_method):
            # Try to find an alternative primary method
            alternatives = {
                "analyze_domain": ["get_domain_info", "domain_analysis"],
                "analyze_ip": ["ip_lookup", "get_ip_info"],
                "analyze_email": ["email_lookup", "check_email"],
                "search_repositories": ["search", "find_repos"],
                "search_academic_sources": ["search", "academic_search"],
                "analyze_crypto_address": ["check_address", "crypto_lookup"],
            }

            found_alternative = False
            for alt in alternatives.get(primary_method, []):
                if hasattr(module_class, alt):
                    primary_method = alt
                    found_alternative = True
                    break

            if not found_alternative:
                continue

        # Apply the wrapper
        try:
            wrapper_func(module_class, primary_method)
            applied_count += 1
        except Exception as e:
            print(f"Warning: Could not apply adapter to {module_name}: {e}")

    return applied_count
