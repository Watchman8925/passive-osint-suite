"""
OSINT Suite Modules Package

This package contains all OSINT (Open Source Intelligence) modules for the Passive OSINT Suite.
All modules inherit from OSINTUtils and provide specialized intelligence gathering capabilities.
"""

# ruff: noqa: E402
# Note: Imports are not at top of file intentionally to allow graceful degradation
# when optional modules are not available. This pattern enables dynamic loading
# with proper error handling for each module.

# Standard library imports
import importlib
import logging
from typing import Any, Dict, List, Type, TypedDict

# Initialize logger
logger = logging.getLogger(__name__)

# Import all module classes for easy access
from .certificate_transparency import CertificateTransparency
from .company_intel import CompanyIntelligence
from .crypto_intel import CryptocurrencyIntelligence
from .darkweb_intel import DarkWebIntelligence
from .document_intel import DocumentIntelligence
from .domain_recon import DomainRecon
from .email_intel import EmailIntelligence
from .financial_intel import FinancialIntelligence
from .flight_intel import FlightIntelligence
from .free_tools import FreeToolsOSINT
from .geospatial_intel import GeospatialIntelligence
from .github_search import GitHubSearch
from .iot_intel import IoTDeviceIntelligence
from .ip_intel import IPIntelligence
from .malware_intel import MalwareThreatIntelligence
from .passive_dns_enum import PassiveDNSEnum
from .passive_search import PassiveSearchIntelligence
from .paste_site_monitor import PasteSiteMonitor
from .preseeded_databases import PreSeededDatabases
from .public_breach_search import PublicBreachSearch
from .rapidapi_osint import RapidAPIOSINTModule
from .search_engine_dorking import SearchEngineDorking
from .social_media_footprint import SocialMediaFootprint
from .wayback_machine import WaybackMachine
from .web_scraper import WebScraper
from .whois_history import WhoisHistory

# Import new enhanced modules
from .digital_forensics import DigitalForensicsAnalyzer
from .code_analysis import CodeAnalysisEngine
from .network_analysis import NetworkAnalysisEngine
from .web_discovery import WebDiscoveryEngine
from .dns_intelligence import DNSIntelligenceEngine
from .pattern_matching import PatternMatchingEngine

# Import new passive intelligence modules
from .gitlab_passive import GitLabPassive
from .bitbucket_passive import BitbucketPassive
from .comprehensive_social_passive import ComprehensiveSocialPassive
from .academic_passive import AcademicPassive
from .patent_passive import PatentPassive

# Import conspiracy analyzer and comprehensive sweep (with error handling)
try:
    # Use dynamic import to avoid static unresolved import errors from linters
    module = importlib.import_module("analysis.conspiracy_analyzer")
    ConspiracyTheoryAnalyzer = getattr(module, "ConspiracyTheoryAnalyzer", None)
    if ConspiracyTheoryAnalyzer is None:
        raise ImportError(
            "ConspiracyTheoryAnalyzer not found in analysis.conspiracy_analyzer"
        )
except Exception as e:
    logger.warning(f"Could not import ConspiracyTheoryAnalyzer: {e}")
    ConspiracyTheoryAnalyzer = None

# Import additional specialized modules from root directory
try:
    # Use dynamic import to avoid static unresolved import errors from linters
    module = importlib.import_module("analysis.hidden_pattern_detector")
    HiddenPatternDetector = getattr(module, "HiddenPatternDetector", None)
    if HiddenPatternDetector is None:
        raise ImportError(
            "HiddenPatternDetector not found in analysis.hidden_pattern_detector"
        )
except Exception as e:
    logger.warning(f"Could not import HiddenPatternDetector: {e}")
    HiddenPatternDetector = None

try:
    # Use dynamic import to avoid static unresolved import errors from linters
    module = importlib.import_module("reporting.reporting_engine")
    EnhancedReportingEngine = getattr(module, "EnhancedReportingEngine", None)
    if EnhancedReportingEngine is None:
        raise ImportError(
            "EnhancedReportingEngine not found in reporting.reporting_engine"
        )
except Exception as e:
    logger.warning(f"Could not import EnhancedReportingEngine: {e}")
    EnhancedReportingEngine = None

try:
    module = importlib.import_module("realtime.realtime_feeds")
    RealTimeIntelligenceFeed = getattr(module, "RealTimeIntelligenceFeed", None)
    if RealTimeIntelligenceFeed is None:
        raise ImportError(
            "RealTimeIntelligenceFeed not found in realtime.realtime_feeds"
        )
except Exception as e:
    logger.warning(f"Could not import RealTimeIntelligenceFeed: {e}")
    RealTimeIntelligenceFeed = None

try:
    # Use dynamic import to avoid static unresolved import errors from linters
    module = importlib.import_module("analysis.cross_reference_engine")
    CrossReferenceEngine = getattr(module, "CrossReferenceEngine", None)
    if CrossReferenceEngine is None:
        raise ImportError(
            "CrossReferenceEngine not found in analysis.cross_reference_engine"
        )
except Exception as e:
    logger.warning(f"Could not import CrossReferenceEngine: {e}")
    CrossReferenceEngine = None

try:
    # Use dynamic import to avoid static unresolved import errors from linters
    module = importlib.import_module("analysis.blackbox_patterns")
    BlackboxPatternEngine = getattr(module, "BlackboxPatternEngine", None)
    if BlackboxPatternEngine is None:
        raise ImportError(
            "BlackboxPatternEngine not found in analysis.blackbox_patterns"
        )
except Exception as e:
    logger.warning(f"Could not import BlackboxPatternEngine: {e}")
    BlackboxPatternEngine = None

try:
    # Use dynamic import to avoid static unresolved import errors from linters
    module = importlib.import_module("bellingcat_toolkit")
    BellingcatToolkit = getattr(module, "BellingcatToolkit", None)
    if BellingcatToolkit is None:
        raise ImportError("BellingcatToolkit not found in bellingcat_toolkit")
except Exception as e:
    logger.warning(f"Could not import BellingcatToolkit: {e}")
    BellingcatToolkit = None

# Import local analysis tools (no API dependencies)
try:
    # Use dynamic import to avoid static unresolved import errors from linters
    module = importlib.import_module("metadata_extractor")
    MetadataExtractor = getattr(module, "MetadataExtractor", None)
    if MetadataExtractor is None:
        raise ImportError("MetadataExtractor not found in metadata_extractor")
except Exception as e:
    logger.warning(f"Could not import MetadataExtractor: {e}")
    MetadataExtractor = None

try:
    module = importlib.import_module("local_dns_enumerator")
    LocalDNSEnumerator = getattr(module, "LocalDNSEnumerator", None)
    if LocalDNSEnumerator is None:
        raise ImportError("LocalDNSEnumerator not found in local_dns_enumerator")
except Exception as e:
    logger.warning(f"Could not import LocalDNSEnumerator: {e}")
    LocalDNSEnumerator = None

try:
    module = importlib.import_module("local_network_analyzer")
    LocalNetworkAnalyzer = getattr(module, "LocalNetworkAnalyzer", None)
    if LocalNetworkAnalyzer is None:
        raise ImportError("LocalNetworkAnalyzer not found in local_network_analyzer")
except Exception as e:
    logger.warning(f"Could not import LocalNetworkAnalyzer: {e}")
    LocalNetworkAnalyzer = None

from .comprehensive_sweep import ComprehensiveInvestigationSweep


class ModuleInfo(TypedDict):
    """Structure for module information in the registry."""

    class_: Type[Any]
    description: str
    category: str


# Module registry for easy discovery and instantiation
MODULE_REGISTRY: Dict[str, Dict[str, Any]] = {
    # Domain and Network Intelligence
    "certificate_transparency": {
        "class": CertificateTransparency,
        "description": "Search certificate transparency logs for subdomains and certificates",
        "category": "domain",
    },
    "domain_recon": {
        "class": DomainRecon,
        "description": "Comprehensive domain reconnaissance and analysis",
        "category": "domain",
    },
    "ip_intel": {
        "class": IPIntelligence,
        "description": "IP address intelligence and geolocation analysis",
        "category": "network",
    },
    "passive_dns_enum": {
        "class": PassiveDNSEnum,
        "description": "Passive DNS enumeration using certificate transparency",
        "category": "network",
    },
    "whois_history": {
        "class": WhoisHistory,
        "description": "WHOIS history and domain registration analysis",
        "category": "domain",
    },
    # Web and Content Analysis
    "web_scraper": {
        "class": WebScraper,
        "description": "Targeted web scraping for keywords and content analysis",
        "category": "web",
    },
    "wayback_machine": {
        "class": WaybackMachine,
        "description": "Historical web snapshots from Internet Archive",
        "category": "web",
    },
    "search_engine_dorking": {
        "class": SearchEngineDorking,
        "description": "Search engine dorking using DuckDuckGo and Bing",
        "category": "web",
    },
    # Social and Public Data
    "social_media_footprint": {
        "class": SocialMediaFootprint,
        "description": "Social media profile discovery and analysis",
        "category": "social",
    },
    "public_breach_search": {
        "class": PublicBreachSearch,
        "description": "Search public breach databases for leaked data",
        "category": "breach",
    },
    "rapidapi_osint": {
        "class": RapidAPIOSINTModule,
        "description": "RapidAPI integration for comprehensive OSINT gathering using free-tier services",
        "category": "general",
    },
    "paste_site_monitor": {
        "class": PasteSiteMonitor,
        "description": "Monitor paste sites for leaked information",
        "category": "breach",
    },
    # Specialized Intelligence
    "company_intel": {
        "class": CompanyIntelligence,
        "description": "Company intelligence and business analysis",
        "category": "business",
    },
    "email_intel": {
        "class": EmailIntelligence,
        "description": "Email address intelligence and breach analysis",
        "category": "email",
    },
    "flight_intel": {
        "class": FlightIntelligence,
        "description": "Aircraft movement and flight intelligence",
        "category": "aviation",
    },
    "crypto_intel": {
        "class": CryptocurrencyIntelligence,
        "description": "Cryptocurrency and blockchain intelligence",
        "category": "crypto",
    },
    "github_search": {
        "class": GitHubSearch,
        "description": "OPSEC-safe GitHub repository searching",
        "category": "code",
    },
    "passive_search": {
        "class": PassiveSearchIntelligence,
        "description": "Multi-platform passive intelligence gathering",
        "category": "general",
    },
    "preseeded_databases": {
        "class": PreSeededDatabases,
        "description": "Access to government and open source intelligence databases (no API keys required)",
        "category": "general",
    },
    "free_tools": {
        "class": FreeToolsOSINT,
        "description": "Local analysis tools and free intelligence gathering (no API dependencies)",
        "category": "general",
    },
    "geospatial_intel": {
        "class": GeospatialIntelligence,
        "description": "Location tracking, mapping, and geographic analysis",
        "category": "geospatial",
    },
    "financial_intel": {
        "class": FinancialIntelligence,
        "description": "Banking records, asset searches, and financial investigations",
        "category": "financial",
    },
    "document_intel": {
        "class": DocumentIntelligence,
        "description": "Document leak monitoring and file sharing analysis",
        "category": "document",
    },
    "darkweb_intel": {
        "class": DarkWebIntelligence,
        "description": "Dark web intelligence and onion routing analysis",
        "category": "darkweb",
    },
    "iot_intel": {
        "class": IoTDeviceIntelligence,
        "description": "IoT device discovery and smart device intelligence",
        "category": "iot",
    },
    "malware_intel": {
        "class": MalwareThreatIntelligence,
        "description": "Malware analysis and threat intelligence feeds",
        "category": "malware",
    },
    # Enhanced Passive Intelligence Modules
    "digital_forensics": {
        "class": DigitalForensicsAnalyzer,
        "description": "Digital forensics and metadata analysis using ExifTool, Tesseract, Zbar",
        "category": "forensics",
    },
    "code_analysis": {
        "class": CodeAnalysisEngine,
        "description": "Code security analysis using GitLeaks, TruffleHog, and Ripgrep",
        "category": "code",
    },
    "network_analysis": {
        "class": NetworkAnalysisEngine,
        "description": "Passive network traffic analysis using tshark (Wireshark)",
        "category": "network",
    },
    "web_discovery": {
        "class": WebDiscoveryEngine,
        "description": "Advanced web crawling and content discovery using httpx, Gau, Waybackurls, Gospider",
        "category": "web",
    },
    "dns_intelligence": {
        "class": DNSIntelligenceEngine,
        "description": "Comprehensive DNS reconnaissance and intelligence using dnsrecon",
        "category": "domain",
    },
    "pattern_matching": {
        "class": PatternMatchingEngine,
        "description": "Security pattern matching and secret detection using Yara and regex patterns",
        "category": "security",
    },
    # Specialized Analysis Modules
    "comprehensive_sweep": {
        "class": ComprehensiveInvestigationSweep,
        "description": "Complete passive investigation sweep across all modules for comprehensive intelligence gathering",
        "category": "orchestration",
    },
    # Advanced Intelligence Analysis Modules
    "hidden_pattern_detector": {
        "class": HiddenPatternDetector,
        "description": "Advanced pattern detection and anomaly identification in intelligence data",
        "category": "analysis",
    },
    "reporting_engine": {
        "class": EnhancedReportingEngine,
        "description": "Comprehensive intelligence reporting and visualization engine",
        "category": "reporting",
    },
    "realtime_feeds": {
        "class": RealTimeIntelligenceFeed,
        "description": "Real-time intelligence feeds and alert monitoring system",
        "category": "monitoring",
    },
    "conspiracy_analyzer": {
        "class": ConspiracyTheoryAnalyzer,
        "description": "Conspiracy theory analysis and misinformation detection",
        "category": "analysis",
    },
    "cross_reference_engine": {
        "class": CrossReferenceEngine,
        "description": "Cross-reference analysis engine for connecting intelligence data points",
        "category": "analysis",
    },
    "blackbox_patterns": {
        "class": BlackboxPatternEngine,
        "description": "Blackbox pattern analysis for unknown threat detection",
        "category": "analysis",
    },
    "bellingcat_toolkit": {
        "class": BellingcatToolkit,
        "description": "Bellingcat-style open source investigation toolkit",
        "category": "investigation",
    },
    "metadata_extractor": {
        "class": MetadataExtractor,
        "description": "Local file metadata extraction and analysis",
        "category": "forensics",
    },
    "local_dns_enumerator": {
        "class": LocalDNSEnumerator,
        "description": "Local DNS enumeration and analysis",
        "category": "network",
    },
    "local_network_analyzer": {
        "class": LocalNetworkAnalyzer,
        "description": "Local network analysis and reconnaissance",
        "category": "network",
    },
    # New Passive Intelligence Modules
    "gitlab_passive": {
        "class": GitLabPassive,
        "description": "Passive GitLab repository and user intelligence gathering",
        "category": "code",
    },
    "bitbucket_passive": {
        "class": BitbucketPassive,
        "description": "Passive Bitbucket repository and user intelligence gathering",
        "category": "code",
    },
    "comprehensive_social_passive": {
        "class": ComprehensiveSocialPassive,
        "description": "Multi-platform social media passive monitoring across 10+ platforms",
        "category": "social",
    },
    "academic_passive": {
        "class": AcademicPassive,
        "description": "Academic and research paper passive intelligence across 6 databases",
        "category": "academic",
    },
    "patent_passive": {
        "class": PatentPassive,
        "description": "Patent database passive intelligence across 4 global patent systems",
        "category": "patent",
    },
}

# Category groupings for easier module discovery
CATEGORIES = {
    "domain": [
        "certificate_transparency",
        "domain_recon",
        "whois_history",
        "dns_intelligence",
    ],
    "network": [
        "ip_intel",
        "passive_dns_enum",
        "network_analysis",
        "local_dns_enumerator",
        "local_network_analyzer",
    ],
    "web": ["web_scraper", "wayback_machine", "search_engine_dorking", "web_discovery"],
    "social": ["social_media_footprint", "comprehensive_social_passive"],
    "breach": ["public_breach_search", "paste_site_monitor"],
    "business": ["company_intel"],
    "email": ["email_intel"],
    "aviation": ["flight_intel"],
    "crypto": ["crypto_intel"],
    "code": ["github_search", "code_analysis", "gitlab_passive", "bitbucket_passive"],
    "patent": ["patent_passive"],
    "analysis": [
        "bellingcat_toolkit",
        "blackbox_patterns",
        "conspiracy_analyzer",
        "cross_reference_engine",
        "hidden_pattern_detector",
    ],
}


def get_module(module_name: str) -> Any:
    """
    Get a module instance by name with dependency injection.

    Args:
        module_name (str): Name of the module to instantiate

    Returns:
        object: Instantiated module object with dependencies injected

    Raises:
        ValueError: If module name is not found
    """
    if module_name not in MODULE_REGISTRY:
        available = list(MODULE_REGISTRY.keys())
        raise ValueError(
            f"Module '{module_name}' not found. Available modules: {available}"
        )

    # Try to use dependency injection
    try:
        from utils.dependency_injection import get_module_with_dependencies

        return get_module_with_dependencies(module_name)
    except ImportError:
        # Fallback to simple instantiation
        module_info = MODULE_REGISTRY[module_name]
        module_class = module_info.get("class")
        if module_class:
            return module_class()
        raise ValueError(f"Module '{module_name}' has no 'class' defined.")


def get_modules_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """
    Get all modules in a specific category.

    Args:
        category (str): Category name

    Returns:
        dict: Dictionary of module_name -> module_info
    """
    if category not in CATEGORIES:
        available = list(CATEGORIES.keys())
        raise ValueError(
            f"Category '{category}' not found. Available categories: {available}"
        )

    return {name: MODULE_REGISTRY[name] for name in CATEGORIES[category]}


def list_modules() -> Dict[str, Dict[str, Any]]:
    """
    List all available modules with their descriptions.

    Returns:
        dict: Module registry information
    """
    return MODULE_REGISTRY


def list_categories() -> Dict[str, List[str]]:
    """
    List all available categories.

    Returns:
        dict: Category information
    """
    return CATEGORIES
    """
    List all available categories.

    Returns:
        dict: Category information
    """
    return CATEGORIES


# Export all module classes and utility functions
__all__ = [
    # Module classes
    "CertificateTransparency",
    "CompanyIntelligence",
    "CryptocurrencyIntelligence",
    "DomainRecon",
    "EmailIntelligence",
    "FinancialIntelligence",
    "FlightIntelligence",
    "GeospatialIntelligence",
    "GitHubSearch",
    "IPIntelligence",
    "PassiveDNSEnum",
    "PassiveSearchIntelligence",
    "PasteSiteMonitor",
    "PublicBreachSearch",
    "SearchEngineDorking",
    "SocialMediaFootprint",
    "WaybackMachine",
    "WebScraper",
    "WhoisHistory",
    "DocumentIntelligence",
    "DarkWebIntelligence",
    "IoTDeviceIntelligence",
    "MalwareThreatIntelligence",
    # New enhanced modules
    "DigitalForensicsAnalyzer",
    "CodeAnalysisEngine",
    "NetworkAnalysisEngine",
    "WebDiscoveryEngine",
    "DNSIntelligenceEngine",
    "PatternMatchingEngine",
    # New Passive Intelligence Modules
    "GitLabPassive",
    "BitbucketPassive",
    "ComprehensiveSocialPassive",
    "AcademicPassive",
    "PatentPassive",
    # Specialized analysis modules
    "ComprehensiveInvestigationSweep",
    # Additional specialized modules
    "HiddenPatternDetector",
    "EnhancedReportingEngine",
    "RealTimeIntelligenceFeed",
    "ConspiracyTheoryAnalyzer",
    "CrossReferenceEngine",
    "BlackboxPatternEngine",
    "BellingcatToolkit",
    # Registry and utilities
    "MODULE_REGISTRY",
    "CATEGORIES",
    "get_module",
    "get_modules_by_category",
    "list_modules",
    "list_categories",
]
