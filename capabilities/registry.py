"""Static capability registry.

Future: dynamic discovery, enable/disable via config, policy filtering.
"""

from . import dns_basic, ssl_cert_fetch, whois_lookup
from .definitions import CapabilityDefinition

# Import new modules
try:
    from modules.digital_forensics import DigitalForensicsAnalyzer
    from modules.code_analysis import CodeAnalysisEngine
    from modules.network_analysis import NetworkAnalysisEngine
    from modules.web_discovery import WebDiscoveryEngine
    from modules.dns_intelligence import DNSIntelligenceEngine
    from modules.pattern_matching import PatternMatchingEngine
except ImportError:
    # Handle case where modules aren't available
    DigitalForensicsAnalyzer = None
    CodeAnalysisEngine = None
    NetworkAnalysisEngine = None
    WebDiscoveryEngine = None
    DNSIntelligenceEngine = None
    PatternMatchingEngine = None

REGISTRY = {
    "dns_basic": CapabilityDefinition(
        id="dns_basic",
        name="Basic DNS Enumeration",
        description="Resolve A/AAAA records for a domain (basic blocking call).",
        category="dns",
        version="0.1.0",
        inputs={"domain": "Domain name to resolve"},
        produces=["domain", "ip"],
        dependencies=(),
        cost_weight=0.5,
        risk_level="low",
        execute=dns_basic.execute,
    ),
    "whois_lookup": CapabilityDefinition(
        id="whois_lookup",
        name="WHOIS Lookup",
        description="Retrieve WHOIS record for a domain (stubbed).",
        category="whois",
        version="0.1.0",
        inputs={"domain": "Domain name"},
        produces=["domain"],
        dependencies=(),
        cost_weight=0.8,
        risk_level="medium",
        execute=whois_lookup.execute,
    ),
    "ssl_cert_fetch": CapabilityDefinition(
        id="ssl_cert_fetch",
        name="SSL Certificate Fetch",
        description="Fetch leaf certificate data for a domain (simplistic).",
        category="ssl",
        version="0.1.0",
        inputs={"domain": "Domain name", "port": "Port (default 443)"},
        produces=["ssl_certificate"],
        dependencies=("dns_basic",),  # Example dependency: ensure DNS resolution first
        cost_weight=0.9,
        risk_level="low",
        execute=ssl_cert_fetch.execute,
    ),
    # Digital Forensics Capabilities
    "digital_forensics_metadata": CapabilityDefinition(
        id="digital_forensics_metadata",
        name="Digital Forensics - Metadata Extraction",
        description="Extract comprehensive metadata from files using ExifTool",
        category="forensics",
        version="1.0.0",
        inputs={"file_path": "Path to file to analyze"},
        produces=["file_metadata", "evidence"],
        dependencies=(),
        cost_weight=1.2,
        risk_level="low",
        execute=lambda context, **inputs: _execute_digital_forensics(
            "extract_metadata", inputs
        ),
    ),
    "digital_forensics_ocr": CapabilityDefinition(
        id="digital_forensics_ocr",
        name="Digital Forensics - OCR Analysis",
        description="Extract text from images using Tesseract OCR",
        category="forensics",
        version="1.0.0",
        inputs={"image_path": "Path to image file", "lang": "Language code (optional)"},
        produces=["ocr_text", "evidence"],
        dependencies=(),
        cost_weight=2.0,
        risk_level="low",
        execute=lambda context, **inputs: _execute_digital_forensics(
            "extract_text_from_image", inputs
        ),
    ),
    "digital_forensics_qr": CapabilityDefinition(
        id="digital_forensics_qr",
        name="Digital Forensics - QR/Barcode Scan",
        description="Scan QR codes and barcodes from images using Zbar",
        category="forensics",
        version="1.0.0",
        inputs={"image_path": "Path to image file"},
        produces=["qr_codes", "barcodes", "evidence"],
        dependencies=(),
        cost_weight=1.5,
        risk_level="low",
        execute=lambda context, **inputs: _execute_digital_forensics(
            "scan_qr_barcodes", inputs
        ),
    ),
    # Code Analysis Capabilities
    "code_analysis_secrets": CapabilityDefinition(
        id="code_analysis_secrets",
        name="Code Analysis - Secret Detection",
        description="Scan git repositories for secrets using GitLeaks and TruffleHog",
        category="code_analysis",
        version="1.0.0",
        inputs={
            "repo_path": "Path to git repository",
            "scan_type": "Scan type (gitleaks, trufflehog, both, all)",
        },
        produces=["secrets", "vulnerabilities", "evidence"],
        dependencies=(),
        cost_weight=3.0,
        risk_level="medium",
        execute=lambda context, **inputs: _execute_code_analysis(
            "scan_git_repository", inputs
        ),
    ),
    "code_analysis_patterns": CapabilityDefinition(
        id="code_analysis_patterns",
        name="Code Analysis - Pattern Search",
        description="Search for sensitive patterns in code using Ripgrep",
        category="code_analysis",
        version="1.0.0",
        inputs={
            "search_path": "Path to search in",
            "patterns": "List of regex patterns",
        },
        produces=["pattern_matches", "evidence"],
        dependencies=(),
        cost_weight=2.5,
        risk_level="low",
        execute=lambda context, **inputs: _execute_code_analysis(
            "search_code_patterns", inputs
        ),
    ),
    # Network Analysis Capabilities
    "network_analysis_pcap": CapabilityDefinition(
        id="network_analysis_pcap",
        name="Network Analysis - PCAP Analysis",
        description="Analyze PCAP files using tshark for traffic patterns",
        category="network",
        version="1.0.0",
        inputs={
            "pcap_path": "Path to PCAP file",
            "analysis_type": "Analysis type (summary, conversations, endpoints, protocols)",
        },
        produces=["network_traffic", "connections", "protocols", "evidence"],
        dependencies=(),
        cost_weight=2.0,
        risk_level="low",
        execute=lambda context, **inputs: _execute_network_analysis(
            "analyze_pcap_file", inputs
        ),
    ),
    "network_analysis_http": CapabilityDefinition(
        id="network_analysis_http",
        name="Network Analysis - HTTP Traffic",
        description="Extract HTTP traffic from PCAP files",
        category="network",
        version="1.0.0",
        inputs={"pcap_path": "Path to PCAP file"},
        produces=["http_requests", "http_responses", "web_traffic", "evidence"],
        dependencies=(),
        cost_weight=1.8,
        risk_level="low",
        execute=lambda context, **inputs: _execute_network_analysis(
            "extract_http_traffic", inputs
        ),
    ),
    # Web Discovery Capabilities
    "web_discovery_wayback": CapabilityDefinition(
        id="web_discovery_wayback",
        name="Web Discovery - Wayback Machine",
        description="Discover URLs from Wayback Machine using Gau",
        category="web_discovery",
        version="1.0.0",
        inputs={
            "domain": "Target domain",
            "include_subs": "Include subdomains (boolean)",
        },
        produces=["urls", "historical_data", "endpoints"],
        dependencies=(),
        cost_weight=2.5,
        risk_level="low",
        execute=lambda context, **inputs: _execute_web_discovery(
            "discover_urls_from_wayback", inputs
        ),
    ),
    "web_discovery_crawl": CapabilityDefinition(
        id="web_discovery_crawl",
        name="Web Discovery - Website Crawling",
        description="Crawl websites using Gospider for content discovery",
        category="web_discovery",
        version="1.0.0",
        inputs={"url": "Target URL", "depth": "Crawl depth (integer)"},
        produces=["urls", "javascript_files", "endpoints", "web_content"],
        dependencies=(),
        cost_weight=3.0,
        risk_level="medium",
        execute=lambda context, **inputs: _execute_web_discovery(
            "crawl_website", inputs
        ),
    ),
    # DNS Intelligence Capabilities
    "dns_intelligence_recon": CapabilityDefinition(
        id="dns_intelligence_recon",
        name="DNS Intelligence - Reconnaissance",
        description="Perform DNS reconnaissance using dnsrecon",
        category="dns_intelligence",
        version="1.0.0",
        inputs={
            "domain": "Target domain",
            "recon_type": "Recon type (standard, brute, axfr, all)",
        },
        produces=["dns_records", "subdomains", "nameservers"],
        dependencies=(),
        cost_weight=2.0,
        risk_level="low",
        execute=lambda context, **inputs: _execute_dns_intelligence(
            "dns_reconnaissance", inputs
        ),
    ),
    "dns_intelligence_subdomains": CapabilityDefinition(
        id="dns_intelligence_subdomains",
        name="DNS Intelligence - Subdomain Enumeration",
        description="Enumerate subdomains using various techniques",
        category="dns_intelligence",
        version="1.0.0",
        inputs={
            "domain": "Target domain",
            "wordlist_path": "Path to wordlist (optional)",
        },
        produces=["subdomains", "dns_records"],
        dependencies=(),
        cost_weight=3.0,
        risk_level="medium",
        execute=lambda context, **inputs: _execute_dns_intelligence(
            "subdomain_enumeration", inputs
        ),
    ),
    # Pattern Matching Capabilities
    "pattern_matching_yara": CapabilityDefinition(
        id="pattern_matching_yara",
        name="Pattern Matching - Yara Scan",
        description="Scan files with Yara rules for malware detection",
        category="pattern_matching",
        version="1.0.0",
        inputs={
            "file_path": "Path to file to scan",
            "rules_path": "Path to Yara rules (optional)",
        },
        produces=["yara_matches", "malware_indicators", "evidence"],
        dependencies=(),
        cost_weight=1.5,
        risk_level="low",
        execute=lambda context, **inputs: _execute_pattern_matching(
            "yara_scan_file", inputs
        ),
    ),
    "pattern_matching_secrets": CapabilityDefinition(
        id="pattern_matching_secrets",
        name="Pattern Matching - Secret Detection",
        description="Find secrets and sensitive data in text using regex patterns",
        category="pattern_matching",
        version="1.0.0",
        inputs={"text": "Text content to analyze"},
        produces=["secrets", "api_keys", "passwords", "evidence"],
        dependencies=(),
        cost_weight=1.0,
        risk_level="medium",
        execute=lambda context, **inputs: _execute_pattern_matching(
            "find_secrets_in_text", inputs
        ),
    ),
    # Conspiracy Analysis Capabilities
    "conspiracy_analysis": CapabilityDefinition(
        id="conspiracy_analysis",
        name="Conspiracy Theory Analysis",
        description="Comprehensive conspiracy theory analysis with evidence-based methodology",
        category="analysis",
        version="1.0.0",
        inputs={
            "theory": "Conspiracy theory description",
            "claims": "List of claims to analyze",
        },
        produces=["analysis_result", "evidence_assessment", "truth_probability"],
        dependencies=(),
        cost_weight=4.0,
        risk_level="medium",
        execute=lambda context, **inputs: _execute_conspiracy_analysis(
            "analyze_theory", inputs
        ),
    ),
    # Comprehensive Sweep Capabilities
    "comprehensive_investigation": CapabilityDefinition(
        id="comprehensive_investigation",
        name="Comprehensive Investigation Sweep",
        description="Complete passive investigation sweep across all modules",
        category="orchestration",
        version="1.0.0",
        inputs={
            "target": "Target to investigate",
            "target_type": "Type of target (domain, ip, email, etc.)",
        },
        produces=["sweep_results", "leads", "pivot_points", "investigation_report"],
        dependencies=(),
        cost_weight=5.0,
        risk_level="low",
        execute=lambda context, **inputs: _execute_comprehensive_sweep(
            "comprehensive_sweep", inputs
        ),
    ),
}

# Global instances for capability execution
_digital_forensics_analyzer = None
_code_analysis_engine = None
_network_analysis_engine = None
_web_discovery_engine = None
_dns_intelligence_engine = None
_pattern_matching_engine = None


def _get_digital_forensics_analyzer():
    global _digital_forensics_analyzer
    if _digital_forensics_analyzer is None and DigitalForensicsAnalyzer:
        _digital_forensics_analyzer = DigitalForensicsAnalyzer()
    return _digital_forensics_analyzer


def _get_code_analysis_engine():
    global _code_analysis_engine
    if _code_analysis_engine is None and CodeAnalysisEngine:
        _code_analysis_engine = CodeAnalysisEngine()
    return _code_analysis_engine


def _get_network_analysis_engine():
    global _network_analysis_engine
    if _network_analysis_engine is None and NetworkAnalysisEngine:
        _network_analysis_engine = NetworkAnalysisEngine()
    return _network_analysis_engine


def _get_web_discovery_engine():
    global _web_discovery_engine
    if _web_discovery_engine is None and WebDiscoveryEngine:
        _web_discovery_engine = WebDiscoveryEngine()
    return _web_discovery_engine


def _get_dns_intelligence_engine():
    global _dns_intelligence_engine
    if _dns_intelligence_engine is None and DNSIntelligenceEngine:
        _dns_intelligence_engine = DNSIntelligenceEngine()
    return _dns_intelligence_engine


def _get_pattern_matching_engine():
    global _pattern_matching_engine
    if _pattern_matching_engine is None and PatternMatchingEngine:
        _pattern_matching_engine = PatternMatchingEngine()
    return _pattern_matching_engine


# Capability execution functions
def _execute_digital_forensics(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("digital_forensics")

    try:
        analyzer = _get_digital_forensics_analyzer()
        if not analyzer:
            return result.mark_complete(False, "Digital forensics module not available")

        method = getattr(analyzer, method_name)
        output = method(**inputs)

        if "error" in output:
            return result.mark_complete(False, output["error"])

        result.produced_entities = [{"type": "evidence", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))


def _execute_code_analysis(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("code_analysis")

    try:
        engine = _get_code_analysis_engine()
        if not engine:
            return result.mark_complete(False, "Code analysis module not available")

        method = getattr(engine, method_name)
        output = method(**inputs)

        if "error" in output:
            return result.mark_complete(False, output["error"])

        result.produced_entities = [{"type": "evidence", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))


def _execute_network_analysis(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("network_analysis")

    try:
        engine = _get_network_analysis_engine()
        if not engine:
            return result.mark_complete(False, "Network analysis module not available")

        method = getattr(engine, method_name)
        output = method(**inputs)

        if "error" in output:
            return result.mark_complete(False, output["error"])

        result.produced_entities = [{"type": "evidence", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))


def _execute_web_discovery(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("web_discovery")

    try:
        engine = _get_web_discovery_engine()
        if not engine:
            return result.mark_complete(False, "Web discovery module not available")

        method = getattr(engine, method_name)
        output = method(**inputs)

        if "error" in output:
            return result.mark_complete(False, output["error"])

        result.produced_entities = [{"type": "evidence", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))


def _execute_dns_intelligence(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("dns_intelligence")

    try:
        engine = _get_dns_intelligence_engine()
        if not engine:
            return result.mark_complete(False, "DNS intelligence module not available")

        method = getattr(engine, method_name)
        output = method(**inputs)

        if "error" in output:
            return result.mark_complete(False, output["error"])

        result.produced_entities = [{"type": "evidence", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))


def _execute_pattern_matching(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("pattern_matching")

    try:
        engine = _get_pattern_matching_engine()
        if not engine:
            return result.mark_complete(False, "Pattern matching module not available")

        method = getattr(engine, method_name)
        output = method(**inputs)

        if "error" in output:
            return result.mark_complete(False, output["error"])

        result.produced_entities = [{"type": "evidence", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))


def _execute_conspiracy_analysis(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("conspiracy_analysis")

    try:
        # Import conspiracy analyzer
        from conspiracy_analyzer import ConspiracyTheoryAnalyzer

        analyzer = ConspiracyTheoryAnalyzer()

        method = getattr(analyzer, method_name)
        output = method(**inputs)

        result.produced_entities = [{"type": "analysis_result", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))


def _execute_comprehensive_sweep(method_name, inputs):
    from .definitions import CapabilityResult

    result = CapabilityResult.start("comprehensive_sweep")

    try:
        # Import comprehensive sweep
        from modules.comprehensive_sweep import ComprehensiveInvestigationSweep

        sweep = ComprehensiveInvestigationSweep()

        method = getattr(sweep, method_name)
        output = method(**inputs)

        result.produced_entities = [{"type": "sweep_results", "data": output}]
        return result.mark_complete(True)

    except Exception as e:
        return result.mark_complete(False, str(e))
