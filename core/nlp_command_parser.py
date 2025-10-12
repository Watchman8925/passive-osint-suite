#!/usr/bin/env python3
"""
Natural Language Command Parser
Converts natural language queries to OSINT module actions
"""

import re
import logging
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CommandIntent(Enum):
    """Types of command intents"""

    INVESTIGATE = "investigate"
    SEARCH = "search"
    ANALYZE = "analyze"
    MONITOR = "monitor"
    REPORT = "report"
    ENUMERATE = "enumerate"
    SCAN = "scan"
    LOOKUP = "lookup"
    UNKNOWN = "unknown"


class TargetType(Enum):
    """Types of investigation targets"""

    DOMAIN = "domain"
    EMAIL = "email"
    IP = "ip"
    PERSON = "person"
    COMPANY = "company"
    USERNAME = "username"
    PHONE = "phone"
    CRYPTOCURRENCY = "crypto"
    URL = "url"
    GITHUB = "github"
    UNKNOWN = "unknown"


@dataclass
class ParsedCommand:
    """Parsed natural language command"""

    intent: CommandIntent
    target_type: TargetType
    target: str
    modules: List[str]
    parameters: Dict[str, Any]
    confidence: float
    raw_command: str


class NLPCommandParser:
    """
    Parse natural language commands and convert them to OSINT actions.

    Examples:
        - "investigate example.com" -> domain_recon
        - "search for email breaches of user@example.com" -> breach_search
        - "analyze social media for john_doe" -> social_media_footprint
        - "find subdomains of example.com" -> subdomain_enum
    """

    def __init__(self):
        """Initialize the NLP command parser"""
        self.intent_keywords = {
            CommandIntent.INVESTIGATE: [
                "investigate",
                "investigate",
                "look into",
                "research",
            ],
            CommandIntent.SEARCH: ["search", "find", "locate", "discover"],
            CommandIntent.ANALYZE: ["analyze", "examine", "assess", "evaluate"],
            CommandIntent.MONITOR: ["monitor", "watch", "track", "observe"],
            CommandIntent.REPORT: ["report", "summarize", "generate report"],
            CommandIntent.ENUMERATE: ["enumerate", "list", "show", "get"],
            CommandIntent.SCAN: ["scan", "probe", "check"],
            CommandIntent.LOOKUP: ["lookup", "whois", "query"],
        }

        self.target_patterns = {
            TargetType.DOMAIN: [
                r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
                r"domain\s+(\S+)",
                r"website\s+(\S+)",
            ],
            TargetType.EMAIL: [
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                r"email\s+(\S+@\S+)",
            ],
            TargetType.IP: [
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                r"ip\s+((?:\d{1,3}\.){3}\d{1,3})",
            ],
            TargetType.PERSON: [
                r"person\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
                r"individual\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
            ],
            TargetType.COMPANY: [
                r"company\s+([A-Z][A-Za-z0-9\s&]+)",
                r"organization\s+([A-Z][A-Za-z0-9\s&]+)",
                r"business\s+([A-Z][A-Za-z0-9\s&]+)",
            ],
            TargetType.USERNAME: [
                r"username\s+(@?\w+)",
                r"user\s+(@?\w+)",
                r"@(\w+)",
            ],
            TargetType.GITHUB: [
                r"github\.com/([a-zA-Z0-9_-]+)",
                r"github\s+user\s+(\w+)",
            ],
        }

        # Module mapping based on intent and target type
        self.module_mapping = {
            (CommandIntent.INVESTIGATE, TargetType.DOMAIN): [
                "domain_recon",
                "dns_intel",
                "certificate_transparency",
            ],
            (CommandIntent.INVESTIGATE, TargetType.EMAIL): [
                "email_intel",
                "breach_search",
            ],
            (CommandIntent.INVESTIGATE, TargetType.IP): [
                "ip_intel",
                "network_analysis",
            ],
            (CommandIntent.INVESTIGATE, TargetType.COMPANY): [
                "company_intel",
                "financial_intel",
            ],
            (CommandIntent.INVESTIGATE, TargetType.USERNAME): [
                "social_media_footprint"
            ],
            (CommandIntent.SEARCH, TargetType.DOMAIN): [
                "search_engine_dorking",
                "wayback_machine",
            ],
            (CommandIntent.SEARCH, TargetType.EMAIL): ["breach_search", "email_intel"],
            (CommandIntent.SEARCH, TargetType.USERNAME): [
                "social_media_footprint",
                "github_search",
            ],
            (CommandIntent.SEARCH, TargetType.COMPANY): ["company_intel"],
            (CommandIntent.ANALYZE, TargetType.DOMAIN): ["domain_recon", "dns_intel"],
            (CommandIntent.ANALYZE, TargetType.EMAIL): ["email_intel"],
            (CommandIntent.ANALYZE, TargetType.IP): ["ip_intel", "network_analysis"],
            (CommandIntent.ENUMERATE, TargetType.DOMAIN): [
                "subdomain_enum",
                "dns_intel",
            ],
            (CommandIntent.LOOKUP, TargetType.DOMAIN): [
                "domain_recon",
                "whois_history",
            ],
            (CommandIntent.LOOKUP, TargetType.IP): ["ip_intel"],
        }

        # Specific keyword to module mapping
        self.keyword_modules = {
            "subdomain": "subdomain_enum",
            "dns": "dns_intel",
            "whois": "whois_history",
            "ssl": "certificate_transparency",
            "certificate": "certificate_transparency",
            "breach": "breach_search",
            "password": "breach_search",
            "social": "social_media_footprint",
            "github": "github_search",
            "dark web": "dark_web_intel",
            "malware": "malware_intel",
            "threat": "threat_intel",
            "crypto": "crypto_intel",
            "blockchain": "crypto_intel",
        }

    def parse(self, command: str) -> ParsedCommand:
        """
        Parse a natural language command.

        Args:
            command: Natural language command string

        Returns:
            ParsedCommand object with parsed intent, target, and modules
        """
        command_lower = command.lower().strip()

        # Detect intent
        intent = self._detect_intent(command_lower)

        # Detect target type and extract target
        target_type, target = self._detect_target(command_lower, command)

        # Determine which modules to use
        modules = self._determine_modules(intent, target_type, command_lower)

        # Extract parameters
        parameters = self._extract_parameters(command_lower)

        # Calculate confidence
        confidence = self._calculate_confidence(intent, target_type, target, modules)

        return ParsedCommand(
            intent=intent,
            target_type=target_type,
            target=target,
            modules=modules,
            parameters=parameters,
            confidence=confidence,
            raw_command=command,
        )

    def _detect_intent(self, command: str) -> CommandIntent:
        """Detect the command intent from keywords"""
        for intent, keywords in self.intent_keywords.items():
            for keyword in keywords:
                if keyword in command:
                    return intent
        return CommandIntent.UNKNOWN

    def _detect_target(
        self, command_lower: str, command_original: str
    ) -> Tuple[TargetType, str]:
        """Detect target type and extract target value"""
        # Try each target type pattern
        for target_type, patterns in self.target_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, command_original, re.IGNORECASE)
                if match:
                    target = match.group(1) if match.lastindex else match.group(0)
                    return target_type, target.strip()

        # If no specific pattern matched, try to extract from command
        words = command_lower.split()
        if len(words) >= 2:
            # Last word might be the target
            potential_target = words[-1]

            # Check if it looks like a domain
            if "." in potential_target and len(potential_target.split(".")) >= 2:
                return TargetType.DOMAIN, potential_target

            # Check if it looks like an email
            if "@" in potential_target:
                return TargetType.EMAIL, potential_target

        return TargetType.UNKNOWN, ""

    def _determine_modules(
        self, intent: CommandIntent, target_type: TargetType, command: str
    ) -> List[str]:
        """Determine which modules should be used"""
        modules = []

        # Get base modules from intent and target type
        base_modules = self.module_mapping.get((intent, target_type), [])
        modules.extend(base_modules)

        # Check for specific keyword mentions
        for keyword, module in self.keyword_modules.items():
            if keyword in command:
                if module not in modules:
                    modules.append(module)

        # If no modules found, provide default comprehensive search
        if not modules:
            if target_type == TargetType.DOMAIN:
                modules = ["domain_recon"]
            elif target_type == TargetType.EMAIL:
                modules = ["email_intel"]
            elif target_type == TargetType.IP:
                modules = ["ip_intel"]

        return modules

    def _extract_parameters(self, command: str) -> Dict[str, Any]:
        """Extract additional parameters from command"""
        parameters = {}

        # Check for depth/recursion
        if "deep" in command or "thorough" in command or "comprehensive" in command:
            parameters["depth"] = "deep"

        # Check for speed preference
        if "quick" in command or "fast" in command:
            parameters["speed"] = "fast"

        # Check for passive/active
        if "passive" in command:
            parameters["mode"] = "passive"
        elif "active" in command:
            parameters["mode"] = "active"

        return parameters

    def _calculate_confidence(
        self,
        intent: CommandIntent,
        target_type: TargetType,
        target: str,
        modules: List[str],
    ) -> float:
        """Calculate confidence score for the parse"""
        confidence = 0.0

        # Intent detected
        if intent != CommandIntent.UNKNOWN:
            confidence += 0.3

        # Target type detected
        if target_type != TargetType.UNKNOWN:
            confidence += 0.3

        # Target extracted
        if target:
            confidence += 0.2

        # Modules selected
        if modules:
            confidence += 0.2

        return min(confidence, 1.0)

    def get_example_commands(self) -> List[str]:
        """Get list of example commands"""
        return [
            "investigate example.com",
            "search for email breaches of user@example.com",
            "analyze social media for john_doe",
            "find subdomains of example.com",
            "lookup whois for example.com",
            "check SSL certificates for example.com",
            "scan IP address 8.8.8.8",
            "search github for username johndoe",
            "investigate company Acme Corp",
            "find breaches for john.doe@example.com",
            "enumerate dns records for example.com",
            "analyze dark web mentions of example.com",
            "lookup crypto address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        ]


# Example usage and testing
if __name__ == "__main__":
    parser = NLPCommandParser()

    print("Natural Language Command Parser - Examples\n")
    print("=" * 60)

    examples = parser.get_example_commands()
    for example in examples:
        result = parser.parse(example)
        print(f"\nCommand: {example}")
        print(f"  Intent: {result.intent.value}")
        print(f"  Target Type: {result.target_type.value}")
        print(f"  Target: {result.target}")
        print(f"  Modules: {', '.join(result.modules)}")
        print(f"  Confidence: {result.confidence:.2f}")
        if result.parameters:
            print(f"  Parameters: {result.parameters}")
