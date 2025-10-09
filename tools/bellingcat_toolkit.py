"""
Bellingcat-style OSINT automation and analysis toolkit.
Implements advanced open-source intelligence techniques without API dependencies.
"""

import hashlib
import json
import logging
import re
import importlib
import importlib.util
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Set, Mapping

## import time  # Unused

# Import our secure transport
try:
    from transport import transport as proxied_transport

    TRANSPORT_AVAILABLE = True
except ImportError:
    TRANSPORT_AVAILABLE = False
    proxied_transport = None  # type: ignore
    logging.warning("Proxied transport not available")

# Import DoH for secure DNS (lazy, to avoid static import errors)
_doh_spec = importlib.util.find_spec("doh_client")
if _doh_spec is not None:
    _doh_mod = importlib.import_module("doh_client")
    doh_client = getattr(_doh_mod, "doh_client", None)
    DOH_AVAILABLE = doh_client is not None
else:
    doh_client = None  # type: ignore
    DOH_AVAILABLE = False
    logging.warning("DoH client not available")

logger = logging.getLogger(__name__)


@dataclass
class InvestigationLead:
    """Represents a lead or clue in an investigation."""

    lead_id: str
    source: str
    content: str
    confidence: float  # 0.0 to 1.0
    timestamp: datetime = field(default_factory=datetime.now)
    lead_type: str = "unknown"  # email, domain, ip, social, file, etc.
    metadata: Dict[str, Any] = field(default_factory=dict)
    related_leads: List[str] = field(default_factory=list)
    verified: bool = False


@dataclass
class TimelineEvent:
    """Represents an event in a chronological timeline."""

    timestamp: datetime
    event_type: str
    description: str
    source: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BellingcatToolkit:
    """
    Advanced OSINT toolkit implementing Bellingcat-style investigation techniques.
    Focuses on automation, verification, and correlation without API dependencies.
    """

    def __init__(self):
        self.leads: Dict[str, InvestigationLead] = {}
        self.timeline: List[TimelineEvent] = []
        self.correlation_cache: Dict[str, Set[str]] = {}
        self.verification_results: Dict[str, Dict[str, Any]] = {}

        # Patterns for various data types
        self.patterns = {
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            "phone": re.compile(
                r"(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}"
            ),
            "ip": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            "bitcoin": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
            "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
            "url": re.compile(r'https?://[^\s<>"]+'),
            "domain": re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
            "hash_md5": re.compile(r"\b[a-f0-9]{32}\b"),
            "hash_sha1": re.compile(r"\b[a-f0-9]{40}\b"),
            "hash_sha256": re.compile(r"\b[a-f0-9]{64}\b"),
            "coordinates": re.compile(r"[-+]?[0-9]*\.?[0-9]+,\s*[-+]?[0-9]*\.?[0-9]+"),
            "imei": re.compile(r"\b[0-9]{15}\b"),
            "ssn": re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"),
            "credit_card": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
            "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"),
            "username": re.compile(r"@[A-Za-z0-9_]+"),
            "hashtag": re.compile(r"#[A-Za-z0-9_]+"),
        }

        logger.info("Bellingcat toolkit initialized")

    def generate_lead_id(self, content: str) -> str:
        """Generate unique ID for a lead using sha256."""
        return hashlib.sha256(content.encode()).hexdigest()[:12]

    def extract_entities(
        self, text: str, source: str = "unknown"
    ) -> List[InvestigationLead]:
        """
        Extract various types of entities from text using regex patterns.
        This is similar to how investigators manually scan documents for leads.
        """
        leads = []

        for entity_type, pattern in self.patterns.items():
            matches = pattern.findall(text)

            for match in matches:
                # Clean up the match
                if isinstance(match, tuple):
                    match = "".join(match)
                match = match.strip()

                if not match:
                    continue

                # Calculate confidence based on pattern complexity and context
                confidence = self._calculate_entity_confidence(match, entity_type, text)

                lead = InvestigationLead(
                    lead_id=self.generate_lead_id(f"{entity_type}:{match}"),
                    source=source,
                    content=match,
                    confidence=confidence,
                    lead_type=entity_type,
                    metadata={
                        "extraction_method": "regex_pattern",
                        "context_snippet": self._get_context(text, match),
                        "position": text.find(match),
                    },
                )

                leads.append(lead)
                self.leads[lead.lead_id] = lead

        logger.info(f"Extracted {len(leads)} entities from {source}")
        return leads

    def _calculate_entity_confidence(
        self, match: str, entity_type: str, context: str
    ) -> float:
        """Calculate confidence score for an extracted entity."""
        base_confidence = 0.7

        # Adjust based on entity type
        type_confidence = {
            "email": 0.9,
            "ip": 0.8,
            "url": 0.9,
            "bitcoin": 0.95,
            "ethereum": 0.95,
            "hash_sha256": 0.85,
            "coordinates": 0.7,
            "phone": 0.8,
        }

        confidence = type_confidence.get(entity_type, base_confidence)

        # Reduce confidence for very common/generic matches
        if entity_type == "domain":
            common_domains = ["example.com", "test.com", "localhost", "google.com"]
            if match.lower() in common_domains:
                confidence *= 0.3

        # Increase confidence if found multiple times
        occurrence_count = context.count(match)
        if occurrence_count > 1:
            confidence = min(1.0, confidence + (occurrence_count - 1) * 0.05)

        return round(confidence, 2)

    def _get_context(self, text: str, match: str, window: int = 50) -> str:
        """Get surrounding context for a match."""
        pos = text.find(match)
        if pos == -1:
            return ""

        start = max(0, pos - window)
        end = min(len(text), pos + len(match) + window)

        return text[start:end].strip()

    async def web_reconnaissance(self, target_url: str) -> Dict[str, Any]:
        """
        Perform comprehensive web reconnaissance similar to Bellingcat techniques.
        Extracts metadata, technologies, and potential leads from web pages.
        """
        if not TRANSPORT_AVAILABLE:
            logger.error("Cannot perform web reconnaissance without transport")
            return {}

        recon_data: Dict[str, Any] = {
            "url": target_url,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "technologies": [],
            "metadata": {},
            "extracted_leads": [],
            "social_links": [],
            "contact_info": [],
            "certificates": {},
            "headers": {},
            "redirects": [],
            "forms": [],
            "comments": [],
        }

        try:
            # Fetch the page
            response = proxied_transport.get(target_url, timeout=30)  # type: ignore[attr-defined]
            recon_data["status"] = response.status_code
            recon_data["headers"] = dict(response.headers)

            if response.status_code != 200:
                return recon_data

            content = response.text

            # Extract metadata from HTML
            recon_data["metadata"] = self._extract_html_metadata(content)

            # Detect technologies
            recon_data["technologies"] = self._detect_technologies(
                content, response.headers
            )

            # Extract entities from content
            leads = self.extract_entities(content, f"web:{target_url}")
            recon_data["extracted_leads"] = [
                {
                    "type": lead.lead_type,
                    "content": lead.content,
                    "confidence": lead.confidence,
                }
                for lead in leads
            ]

            # Find social media links
            recon_data["social_links"] = self._extract_social_links(content)

            # Extract contact information
            recon_data["contact_info"] = self._extract_contact_info(content)

            # Extract forms (potential attack vectors or data collection points)
            recon_data["forms"] = self._extract_forms(content)

            # Extract HTML comments (often contain sensitive info)
            recon_data["comments"] = self._extract_html_comments(content)

            logger.info(f"Web reconnaissance completed for {target_url}")

        except Exception as e:
            logger.error(f"Web reconnaissance failed for {target_url}: {e}")
            recon_data["error"] = str(e)

        return recon_data

    def _extract_html_metadata(self, html_content: str) -> Dict[str, Any]:
        """Extract metadata from HTML."""
        metadata = {}

        # Title
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL
        )
        if title_match:
            metadata["title"] = title_match.group(1).strip()

        # Meta tags
        meta_pattern = re.compile(r"<meta\s+([^>]+)>", re.IGNORECASE)
        for meta_match in meta_pattern.finditer(html_content):
            meta_attrs = meta_match.group(1)

            # Parse attributes
            name_match = re.search(
                r'name=["\']([^"\']+)["\']', meta_attrs, re.IGNORECASE
            )
            property_match = re.search(
                r'property=["\']([^"\']+)["\']', meta_attrs, re.IGNORECASE
            )
            content_match = re.search(
                r'content=["\']([^"\']*)["\']', meta_attrs, re.IGNORECASE
            )

            if content_match:
                content = content_match.group(1)
                if name_match:
                    metadata[f"meta_{name_match.group(1)}"] = content
                elif property_match:
                    metadata[f"property_{property_match.group(1)}"] = content

        return metadata

    def _detect_technologies(
        self, html_content: str, headers: Mapping[str, str]
    ) -> List[str]:
        """Detect technologies used by the website."""
        technologies = []

        # Check headers
        if "server" in headers:
            technologies.append(f"Server: {headers['server']}")

        if "x-powered-by" in headers:
            technologies.append(f"Powered by: {headers['x-powered-by']}")

        # Check HTML content for technology indicators
        tech_indicators = {
            "WordPress": [r"wp-content", r"wp-includes", r"/wp-json/"],
            "Drupal": [r"sites/default", r"drupal\.js"],
            "Joomla": [r"joomla", r"administrator/index\.php"],
            "React": [r"react", r"__REACT_DEVTOOLS"],
            "Angular": [r"ng-", r"angular"],
            "Vue.js": [r"vue\.js", r"__vue__"],
            "jQuery": [r"jquery", r"\$\("],
            "Bootstrap": [r"bootstrap", r"btn-"],
            "Google Analytics": [r"google-analytics", r"gtag", r"ga\("],
            "Facebook Pixel": [r"fbevents\.js", r"facebook\.net"],
            "Cloudflare": [r"cloudflare", r"__cf_bm"],
            "Google Tag Manager": [r"googletagmanager"],
        }

        for tech, patterns in tech_indicators.items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    technologies.append(tech)
                    break

        return list(set(technologies))

    def _extract_social_links(self, html_content: str) -> List[Dict[str, str]]:
        """Extract social media links."""
        social_platforms = {
            "twitter": r"twitter\.com/[A-Za-z0-9_]+",
            "facebook": r"facebook\.com/[A-Za-z0-9.]+",
            "instagram": r"instagram\.com/[A-Za-z0-9_.]+",
            "linkedin": r"linkedin\.com/[A-Za-z0-9/]+",
            "youtube": r"youtube\.com/[A-Za-z0-9/]+",
            "github": r"github\.com/[A-Za-z0-9-]+",
            "telegram": r"t\.me/[A-Za-z0-9_]+",
            "tiktok": r"tiktok\.com/@[A-Za-z0-9_.]+",
        }

        social_links = []

        for platform, pattern in social_platforms.items():
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                social_links.append(
                    {
                        "platform": platform,
                        "url": f"https://{match.group(0)}",
                        "username": match.group(0).split("/")[-1],
                    }
                )

        return social_links

    def _extract_contact_info(self, html_content: str) -> List[Dict[str, str]]:
        """Extract contact information."""
        contacts = []

        # Email addresses
        email_matches = self.patterns["email"].finditer(html_content)
        for match in email_matches:
            contacts.append(
                {
                    "type": "email",
                    "value": match.group(0),
                    "context": self._get_context(html_content, match.group(0)),
                }
            )

        # Phone numbers
        phone_matches = self.patterns["phone"].finditer(html_content)
        for match in phone_matches:
            contacts.append(
                {
                    "type": "phone",
                    "value": match.group(0),
                    "context": self._get_context(html_content, match.group(0)),
                }
            )

        return contacts

    def _extract_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """Extract forms which might be interesting for OSINT."""
        forms = []

        form_pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)

        for form_match in form_pattern.finditer(html_content):
            form_html = form_match.group(0)

            # Extract form attributes
            action_match = re.search(
                r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE
            )
            method_match = re.search(
                r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE
            )

            # Extract input fields
            input_pattern = re.compile(r"<input[^>]*>", re.IGNORECASE)
            inputs = []

            for input_match in input_pattern.finditer(form_html):
                input_html = input_match.group(0)
                name_match = re.search(
                    r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE
                )
                type_match = re.search(
                    r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE
                )

                if name_match:
                    inputs.append(
                        {
                            "name": name_match.group(1),
                            "type": type_match.group(1) if type_match else "text",
                        }
                    )

            forms.append(
                {
                    "action": action_match.group(1) if action_match else "",
                    "method": method_match.group(1) if method_match else "GET",
                    "inputs": inputs,
                }
            )

        return forms

    def _extract_html_comments(self, html_content: str) -> List[str]:
        """Extract HTML comments which often contain sensitive information."""
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        comments = []

        for match in comment_pattern.finditer(html_content):
            comment = match.group(1).strip()
            if comment and len(comment) > 10:  # Filter out empty or very short comments
                comments.append(comment)

        return comments

    async def domain_investigation(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive domain investigation using passive techniques.
        Similar to what Bellingcat investigators do for domain analysis.
        """
        investigation: Dict[str, Any] = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "dns_records": {},
            "subdomains": [],
            "certificates": {},
            "whois_indicators": {},
            "technology_stack": [],
            "security_headers": {},
            "redirects": [],
            "related_domains": [],
        }

        # DNS enumeration
        if DOH_AVAILABLE and doh_client is not None:
            dns_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]
            for record_type in dns_types:
                try:
                    response = await doh_client.resolve(domain, record_type)
                    if response.answers:
                        investigation["dns_records"][record_type] = [
                            answer.data for answer in response.answers
                        ]
                except Exception as e:
                    logger.debug(
                        f"DNS resolution failed for {domain} {record_type}: {e}"
                    )

        # Subdomain enumeration using certificate transparency logs
        investigation["subdomains"] = await self._enumerate_subdomains_ct(domain)

        # Web reconnaissance
        try:
            web_recon = await self.web_reconnaissance(f"https://{domain}")
            investigation["technology_stack"] = web_recon.get("technologies", [])
            investigation["security_headers"] = self._analyze_security_headers(
                web_recon.get("headers", {})
            )
        except Exception as e:
            logger.debug(f"Web reconnaissance failed for {domain}: {e}")

        return investigation

    async def _enumerate_subdomains_ct(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using Certificate Transparency logs.
        This is a passive technique that doesn't alert the target.
        """
        subdomains: Set[str] = set()

        if not TRANSPORT_AVAILABLE:
            return list(subdomains)

        ct_apis = [
            f"https://crt.sh/?q={domain}&output=json",
            # Add more CT log APIs as needed
        ]

        for api_url in ct_apis:
            try:
                response = proxied_transport.get(api_url, timeout=30)  # type: ignore[attr-defined]
                if response.status_code == 200:
                    try:
                        ct_data = response.json()
                        for entry in ct_data:
                            if "name_value" in entry:
                                names = entry["name_value"].split("\n")
                                for name in names:
                                    name = name.strip()
                                    if name.endswith(f".{domain}") or name == domain:
                                        subdomains.add(name)
                    except (json.JSONDecodeError, KeyError):
                        pass

            except Exception as e:
                logger.debug(f"CT log query failed for {domain}: {e}")

        return list(subdomains)

    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers for potential vulnerabilities."""
        security_analysis: Dict[str, Any] = {
            "score": 0,
            "missing_headers": [],
            "weak_headers": [],
            "good_headers": [],
        }

        security_headers = {
            "strict-transport-security": {"weight": 20, "name": "HSTS"},
            "content-security-policy": {"weight": 25, "name": "CSP"},
            "x-frame-options": {"weight": 15, "name": "X-Frame-Options"},
            "x-content-type-options": {"weight": 10, "name": "X-Content-Type-Options"},
            "x-xss-protection": {"weight": 10, "name": "X-XSS-Protection"},
            "referrer-policy": {"weight": 10, "name": "Referrer-Policy"},
            "permissions-policy": {"weight": 10, "name": "Permissions-Policy"},
        }

        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, config in security_headers.items():
            if header in headers_lower:
                security_analysis["score"] += config["weight"]
                security_analysis["good_headers"].append(config["name"])
            else:
                security_analysis["missing_headers"].append(config["name"])

        return security_analysis

    def correlate_leads(self, lead_ids: List[str]) -> Dict[str, Any]:
        """
            Correlate multiple leads to find connections.
        This is similar to how investigators connect dots between
        different pieces of evidence.
        """
        correlation: Dict[str, Any] = {
            "lead_ids": lead_ids,
            "connections": [],
            "common_attributes": {},
            "timeline_overlap": [],
            "confidence_score": 0.0,
        }

        leads = [self.leads[lid] for lid in lead_ids if lid in self.leads]

        if len(leads) < 2:
            return correlation

        # Find common sources
        sources = [lead.source for lead in leads]
        if len(set(sources)) < len(sources):
            correlation["connections"].append(
                {
                    "type": "common_source",
                    "details": f"Multiple leads from same source: {sources[0]}",
                }
            )

        # Find temporal correlations
        timestamps = [lead.timestamp for lead in leads]
        time_diffs = []
        for i in range(len(timestamps) - 1):
            diff = abs((timestamps[i] - timestamps[i + 1]).total_seconds())
            time_diffs.append(diff)

        if time_diffs and max(time_diffs) < 3600:  # Within 1 hour
            correlation["connections"].append(
                {
                    "type": "temporal_correlation",
                    "details": f"Leads discovered within {max(time_diffs)/60:.1f} minutes",
                }
            )

        # Find content similarities
        contents = [lead.content for lead in leads]
        for i, content1 in enumerate(contents):
            for j, content2 in enumerate(contents[i + 1 :], i + 1):
                similarity = self._calculate_content_similarity(content1, content2)
                if similarity > 0.7:
                    correlation["connections"].append(
                        {
                            "type": "content_similarity",
                            "details": (
                                f"High similarity between leads {i} and {j}: "
                                f"{similarity:.2f}"
                            ),
                        }
                    )

        # Calculate overall confidence
        correlation["confidence_score"] = min(
            1.0, len(correlation["connections"]) * 0.3
        )

        return correlation

    def _calculate_content_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity between two pieces of content."""
        # Simple character-based similarity
        if not content1 or not content2:
            return 0.0

        # Convert to sets of characters
        set1 = set(content1.lower())
        set2 = set(content2.lower())

        # Jaccard similarity
        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    def build_timeline(self, leads: List[str]) -> List[TimelineEvent]:
        """
        Build a chronological timeline from investigation leads.
        Essential for understanding the sequence of events.
        """
        timeline_events = []

        for lead_id in leads:
            if lead_id not in self.leads:
                continue

            lead = self.leads[lead_id]

            event = TimelineEvent(
                timestamp=lead.timestamp,
                event_type=f"lead_discovered_{lead.lead_type}",
                description=f"Discovered {lead.lead_type}: {lead.content}",
                source=lead.source,
                confidence=lead.confidence,
                evidence=[lead_id],
                metadata={"lead_id": lead_id},
            )

            timeline_events.append(event)

        # Sort by timestamp
        timeline_events.sort(key=lambda x: x.timestamp)

        return timeline_events

    def generate_investigation_report(
        self, title: str = "OSINT Investigation"
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive investigation report.
        Similar to the reports Bellingcat publishes.
        """
        report: Dict[str, Any] = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_leads": len(self.leads),
                "lead_types": {},
                "high_confidence_leads": 0,
                "verified_leads": 0,
            },
            "leads_by_type": {},
            "timeline": [],
            "correlations": [],
            "recommendations": [],
        }

        # Analyze leads
        for lead in self.leads.values():
            # Count by type
            if lead.lead_type not in report["summary"]["lead_types"]:
                report["summary"]["lead_types"][lead.lead_type] = 0
            report["summary"]["lead_types"][lead.lead_type] += 1

            # Group by type for detailed analysis
            if lead.lead_type not in report["leads_by_type"]:
                report["leads_by_type"][lead.lead_type] = []

            report["leads_by_type"][lead.lead_type].append(
                {
                    "content": lead.content,
                    "source": lead.source,
                    "confidence": lead.confidence,
                    "timestamp": lead.timestamp.isoformat(),
                    "verified": lead.verified,
                }
            )

            # Count high confidence and verified leads
            if lead.confidence > 0.8:
                report["summary"]["high_confidence_leads"] += 1

            if lead.verified:
                report["summary"]["verified_leads"] += 1

        # Generate timeline
        all_lead_ids = list(self.leads.keys())
        report["timeline"] = [
            {
                "timestamp": event.timestamp.isoformat(),
                "type": event.event_type,
                "description": event.description,
                "source": event.source,
                "confidence": event.confidence,
            }
            for event in self.build_timeline(all_lead_ids)
        ]

        # Generate recommendations
        report["recommendations"] = self._generate_investigation_recommendations()

        return report

    def _generate_investigation_recommendations(self) -> List[str]:
        """Generate recommendations for further investigation."""
        recommendations = []

        # Check lead distribution
        lead_types: Dict[str, int] = {}
        for lead in self.leads.values():
            lead_types[lead.lead_type] = lead_types.get(lead.lead_type, 0) + 1

        if "email" in lead_types and lead_types["email"] > 0:
            recommendations.append(
                "Consider investigating email addresses for breach data "
                "and associated accounts"
            )

        if "domain" in lead_types and lead_types["domain"] > 0:
            recommendations.append(
                "Perform detailed domain analysis including subdomain "
                "enumeration and historical data"
            )

        if "ip" in lead_types and lead_types["ip"] > 0:
            recommendations.append(
                "Investigate IP addresses for hosting history, geolocation, "
                "and network associations"
            )

        # Check for low confidence leads
        low_confidence_count = sum(
            1 for lead in self.leads.values() if lead.confidence < 0.5
        )
        if low_confidence_count > 0:
            recommendations.append(
                f"Verify {low_confidence_count} low-confidence leads "
                "through additional sources"
            )

        # Check for unverified high-confidence leads
        unverified_high_conf = sum(
            1
            for lead in self.leads.values()
            if lead.confidence > 0.8 and not lead.verified
        )
        if unverified_high_conf > 0:
            recommendations.append(
                f"Prioritize verification of {unverified_high_conf} "
                "high-confidence leads"
            )

        return recommendations

    def export_leads_csv(self) -> str:
        """Export leads to CSV format for analysis in external tools."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(
            [
                "Lead ID",
                "Type",
                "Content",
                "Source",
                "Confidence",
                "Timestamp",
                "Verified",
                "Context",
            ]
        )

        # Data
        for lead in self.leads.values():
            writer.writerow(
                [
                    lead.lead_id,
                    lead.lead_type,
                    lead.content,
                    lead.source,
                    lead.confidence,
                    lead.timestamp.isoformat(),
                    lead.verified,
                    lead.metadata.get("context_snippet", ""),
                ]
            )

        return output.getvalue()


# Global toolkit instance
bellingcat_toolkit = BellingcatToolkit()


async def investigate_target(target: str, target_type: str = "auto") -> Dict[str, Any]:
    """
    Convenience function to investigate a target using Bellingcat techniques.

    Args:
        target: The target to investigate (URL, domain, text, etc.)
        target_type: Type of target ('url', 'domain', 'text', 'auto')

    Returns:
        Investigation results
    """
    if target_type == "auto":
        # Auto-detect target type
        if target.startswith(("http://", "https://")):
            target_type = "url"
        elif "." in target and " " not in target:
            target_type = "domain"
        else:
            target_type = "text"

    if target_type == "url":
        return await bellingcat_toolkit.web_reconnaissance(target)
    elif target_type == "domain":
        return await bellingcat_toolkit.domain_investigation(target)
    elif target_type == "text":
        leads = bellingcat_toolkit.extract_entities(target, "manual_input")
        return {
            "target": target,
            "extracted_leads": [
                {
                    "type": lead.lead_type,
                    "content": lead.content,
                    "confidence": lead.confidence,
                }
                for lead in leads
            ],
        }
    else:
        raise ValueError(f"Unknown target type: {target_type}")


def get_investigation_summary() -> Dict[str, Any]:
    """Get summary of current investigation state."""
    return bellingcat_toolkit.generate_investigation_report()
