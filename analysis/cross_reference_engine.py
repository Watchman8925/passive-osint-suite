"""
Cross-Reference Intelligence Engine
===================================

Advanced intelligence correlation system that pulls from leak databases,
archives, and open sources to uncover hidden patterns, conspiracy networks,
and transnational organized crime operations through layers of plausible deniability.

This engine specifically focuses on:
- Truth-seeking through multi-angle analysis
- Hidden pattern detection most analysts miss
- Conspiracy theory validation/debunking with evidence
- Transnational crime network mapping
- Plausible deniability layer penetration
"""

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from bs4 import BeautifulSoup

# Lazy import to avoid circular dependencies
from local_llm_engine import LocalLLMEngine
from transport import Transport, sync_get, ProxiedTransport

logger = logging.getLogger(__name__)


@dataclass
class IntelligenceSource:
    """Represents an intelligence source for cross-reference."""

    source_id: str
    source_name: str
    source_type: str  # leak_db, archive, news, government, social
    base_url: str
    api_endpoint: Optional[str] = None
    requires_api_key: bool = False
    credibility_score: float = 0.8
    access_method: str = "web_scraping"  # web_scraping, api, tor_required
    rate_limit: int = 1  # Seconds between requests


@dataclass
class CrossReferenceHit:
    """Represents a cross-reference intelligence hit."""

    hit_id: str
    source: str
    title: str
    content: str
    url: str
    timestamp: datetime
    confidence: float
    relevance_score: float
    patterns_detected: List[str] = field(default_factory=list)
    hidden_indicators: List[str] = field(default_factory=list)
    conspiracy_markers: List[str] = field(default_factory=list)


@dataclass
class ConspiracyTheory:
    """Represents a conspiracy theory for analysis."""

    theory_id: str
    title: str
    description: str
    key_claims: List[str]
    key_actors: List[str]
    key_events: List[str]
    evidence_for: List[CrossReferenceHit] = field(default_factory=list)
    evidence_against: List[CrossReferenceHit] = field(default_factory=list)
    plausibility_score: float = 0.0
    truth_indicators: List[str] = field(default_factory=list)
    disinformation_markers: List[str] = field(default_factory=list)


@dataclass
class LLMAnalysisResult:
    insights: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)


class CrossReferenceEngine:
    """
    Advanced cross-reference intelligence engine for deep OSINT analysis.

    This engine specializes in uncovering hidden connections, analyzing
    conspiracy theories, and penetrating layers of plausible deniability
    used by transnational organized crime groups.
    """

    def __init__(self):
        self.sources = {}
        self.transport = Transport()
        self.llm_engine = LocalLLMEngine()
        self.pattern_engine = None  # Lazy load to avoid circular imports

        # Initialize intelligence sources
        self._initialize_sources()

        # Initialize conspiracy analysis patterns
        self._initialize_conspiracy_patterns()

        # Initialize hidden pattern detection
        self._initialize_hidden_patterns()

    def _get_pattern_engine(self):
        """Lazy load pattern engine to avoid circular imports"""
        if self.pattern_engine is None:
            try:
                from .blackbox_patterns import BlackboxPatternEngine

                self.pattern_engine = BlackboxPatternEngine()
            except ImportError:
                try:
                    from blackbox_patterns import BlackboxPatternEngine

                    self.pattern_engine = BlackboxPatternEngine()
                except ImportError:
                    # Fallback no-op engine
                    class NoOpPatternEngine:
                        def analyze_patterns(self, *args, **kwargs):
                            return {"patterns": [], "confidence": 0.0}

                    self.pattern_engine = NoOpPatternEngine()
        return self.pattern_engine

    def _initialize_sources(self):
        """Initialize comprehensive intelligence sources."""

        # Leak databases and archives
        self.sources.update(
            {
                "wikileaks": IntelligenceSource(
                    source_id="wikileaks",
                    source_name="WikiLeaks",
                    source_type="leak_db",
                    base_url="https://wikileaks.org",
                    credibility_score=0.9,
                    access_method="web_scraping",
                ),
                "wayback_machine": IntelligenceSource(
                    source_id="wayback_machine",
                    source_name="Internet Archive Wayback Machine",
                    source_type="archive",
                    base_url="https://web.archive.org",
                    api_endpoint="https://web.archive.org/wayback/available",
                    credibility_score=0.95,
                    access_method="api",
                ),
                "archive_today": IntelligenceSource(
                    source_id="archive_today",
                    source_name="Archive.today",
                    source_type="archive",
                    base_url="https://archive.today",
                    credibility_score=0.85,
                    access_method="web_scraping",
                ),
                "cryptome": IntelligenceSource(
                    source_id="cryptome",
                    source_name="Cryptome",
                    source_type="leak_db",
                    base_url="https://cryptome.org",
                    credibility_score=0.8,
                    access_method="web_scraping",
                ),
                "ddosecrets": IntelligenceSource(
                    source_id="ddosecrets",
                    source_name="Distributed Denial of Secrets",
                    source_type="leak_db",
                    base_url="https://ddosecrets.com",
                    credibility_score=0.85,
                    access_method="web_scraping",
                ),
                "icij_offshoreleaks": IntelligenceSource(
                    source_id="icij_offshoreleaks",
                    source_name="ICIJ Offshore Leaks Database",
                    source_type="leak_db",
                    base_url="https://offshoreleaks.icij.org",
                    credibility_score=0.95,
                    access_method="web_scraping",
                ),
                "panama_papers": IntelligenceSource(
                    source_id="panama_papers",
                    source_name="Panama Papers",
                    source_type="leak_db",
                    base_url="https://panamapapers.icij.org",
                    credibility_score=0.95,
                    access_method="web_scraping",
                ),
                "paradise_papers": IntelligenceSource(
                    source_id="paradise_papers",
                    source_name="Paradise Papers",
                    source_type="leak_db",
                    base_url="https://paradisepapers.icij.org",
                    credibility_score=0.95,
                    access_method="web_scraping",
                ),
                "pandora_papers": IntelligenceSource(
                    source_id="pandora_papers",
                    source_name="Pandora Papers",
                    source_type="leak_db",
                    base_url="https://pandorapapers.icij.org",
                    credibility_score=0.95,
                    access_method="web_scraping",
                ),
                "wikispooks": IntelligenceSource(
                    source_id="wikispooks",
                    source_name="Wikispooks",
                    source_type="intelligence_wiki",
                    base_url="https://wikispooks.com",
                    credibility_score=0.7,
                    access_method="web_scraping",
                ),
                "constellations": IntelligenceSource(
                    source_id="constellations",
                    source_name="Constellations of International Crime",
                    source_type="crime_db",
                    base_url="https://constellations.occrp.org",
                    credibility_score=0.9,
                    access_method="web_scraping",
                ),
                "investigative_dashboard": IntelligenceSource(
                    source_id="investigative_dashboard",
                    source_name="OCCRP Investigative Dashboard",
                    source_type="investigation_tools",
                    base_url="https://id.occrp.org",
                    credibility_score=0.9,
                    access_method="web_scraping",
                ),
            }
        )

    def _initialize_conspiracy_patterns(self):
        """Initialize patterns for conspiracy theory analysis."""

        self.conspiracy_patterns = {
            "disinformation_markers": [
                r"(they don\'t want you to know|wake up sheeple|mainstream media lies)",
                r"(false flag|crisis actor|staged event)",
                r"(new world order|illuminati|deep state conspiracy)",
                r"(think for yourself|do your own research|question everything)",
                r"(cover[- ]?up|conspiracy|hidden truth|secret agenda)",
            ],
            "truth_indicators": [
                r"(documented evidence|official records|leaked documents)",
                r"(court records|legal proceedings|testimony under oath)",
                r"(financial records|bank statements|transactions)",
                r"(verified by multiple sources|corroborated|cross-referenced)",
                r"(investigative journalism|fact-checked|peer-reviewed)",
            ],
            "plausible_deniability_layers": [
                r"(shell company|offshore entity|proxy organization)",
                r"(cutout|front organization|charitable foundation)",
                r"(consulting firm|advisory board|board of directors)",
                r"(family trust|investment fund|holding company)",
                r"(nominee director|beneficial owner|ultimate beneficial owner)",
            ],
            "organized_crime_indicators": [
                r"(money laundering|financial crime|proceeds of crime)",
                r"(corruption|bribery|kickback|political influence)",
                r"(drug trafficking|human trafficking|arms dealing)",
                r"(racketeering|extortion|protection racket)",
                r"(criminal organization|syndicate|cartel|mafia)",
            ],
            "hidden_connection_patterns": [
                r"(undisclosed relationship|hidden ownership|secret partnership)",
                r"(off-the-books|under the table|backdoor deal)",
                r"(informal arrangement|gentleman\'s agreement|handshake deal)",
                r"(family connection|personal relationship|old school tie)",
                r"(revolving door|conflict of interest|insider information)",
            ],
        }

    def _initialize_hidden_patterns(self):
        """Initialize patterns for detecting hidden connections most analysts miss."""

        self.hidden_patterns = {
            "temporal_correlations": {
                "description": "Events happening suspiciously close in time",
                "detection_window": timedelta(days=30),
                "significance_threshold": 0.8,
            },
            "geographic_clustering": {
                "description": "Unusual geographic concentrations of activity",
                "proximity_threshold": 50,  # kilometers
                "cluster_threshold": 3,  # minimum events for cluster
            },
            "financial_flow_patterns": {
                "description": "Suspicious financial transaction patterns",
                "amount_thresholds": [
                    9999,
                    49999,
                    99999,
                ],  # Just under reporting thresholds
                "velocity_indicators": [
                    "rapid succession",
                    "round numbers",
                    "exact amounts",
                ],
            },
            "communication_patterns": {
                "description": "Hidden communication and coordination indicators",
                "indicators": [
                    "simultaneous actions",
                    "coordinated messaging",
                    "synchronized timing",
                ],
            },
            "misdirection_tactics": {
                "description": "Deliberate misdirection and distraction patterns",
                "indicators": [
                    "information overload",
                    "red herrings",
                    "false controversies",
                ],
            },
        }

    async def cross_reference_search(
        self,
        query: str,
        target_sources: Optional[List[str]] = None,
        search_mode: str = "comprehensive",
    ) -> List[CrossReferenceHit]:
        """
        Perform comprehensive cross-reference search across multiple intelligence sources.

        Args:
            query: Search query or target to investigate
            target_sources: Specific sources to search (default: all sources)
            search_mode: 'comprehensive', 'conspiracy_focus', 'crime_focus', 'hidden_patterns'

        Returns:
            List of cross-reference hits with intelligence data
        """
        hits = []

        try:
            sources_to_search = target_sources or list(self.sources.keys())

            # Filter sources based on search mode
            if search_mode == "conspiracy_focus":
                sources_to_search = [
                    s
                    for s in sources_to_search
                    if self.sources[s].source_type in ["leak_db", "intelligence_wiki"]
                ]
            elif search_mode == "crime_focus":
                sources_to_search = [
                    s
                    for s in sources_to_search
                    if self.sources[s].source_type in ["leak_db", "crime_db"]
                ]

            # Search each source
            for source_id in sources_to_search:
                try:
                    source_hits = await self._search_source(source_id, query)
                    hits.extend(source_hits)

                    # Rate limiting
                    await asyncio.sleep(self.sources[source_id].rate_limit)

                except Exception as e:
                    logger.warning(f"Search failed for source {source_id}: {e}")
                    continue

            # Enhance hits with pattern analysis
            enhanced_hits = await self._enhance_hits_with_patterns(hits, query)

            # Score and rank hits
            ranked_hits = self._rank_hits_by_relevance(
                enhanced_hits, query, search_mode
            )

            return ranked_hits

        except Exception as e:
            logger.error(f"Cross-reference search failed: {e}")
            return []

    async def _search_source(
        self, source_id: str, query: str
    ) -> List[CrossReferenceHit]:
        """Search a specific intelligence source."""
        hits = []
        source = self.sources[source_id]

        try:
            if source.access_method == "api":
                hits = await self._search_via_api(source, query)
            elif source.access_method == "web_scraping":
                hits = await self._search_via_scraping(source, query)
            elif source.access_method == "tor_required":
                hits = await self._search_via_tor(source, query)

            # Add source credibility to confidence scores
            for hit in hits:
                hit.confidence *= source.credibility_score

            return hits

        except Exception as e:
            logger.error(f"Source search failed for {source_id}: {e}")
            return []

    async def _search_via_api(
        self, source: IntelligenceSource, query: str
    ) -> List[CrossReferenceHit]:
        """Search source via API."""
        hits = []

        try:
            if source.source_id == "wayback_machine":
                # Wayback Machine API search
                api_url = f"{source.api_endpoint}?url={quote(query)}"
                response = sync_get(api_url)

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "archived_snapshots" in data:
                            snapshots = data["archived_snapshots"]
                            if "closest" in snapshots:
                                snapshot = snapshots["closest"]

                                hit = CrossReferenceHit(
                                    hit_id=f"wayback_{hashlib.md5(query.encode()).hexdigest()[:8]}",
                                    source=source.source_name,
                                    title=f"Archived: {query}",
                                    content=f"Archived snapshot from {snapshot.get('timestamp', 'unknown')}",
                                    url=snapshot.get("url", ""),
                                    timestamp=datetime.now(),
                                    confidence=0.9,
                                    relevance_score=0.8,
                                )
                                hits.append(hit)
                    except Exception as e:
                        logger.warning(f"Failed to parse Wayback API response: {e}")

            return hits

        except Exception as e:
            logger.error(f"API search failed for {source.source_name}: {e}")
            return []

    async def _search_via_scraping(
        self, source: IntelligenceSource, query: str
    ) -> List[CrossReferenceHit]:
        """Search source via web scraping."""
        hits = []

        try:
            # Construct search URL based on source
            search_urls = self._construct_search_urls(source, query)

            for search_url in search_urls:
                try:
                    # Use anonymous request through our existing system
                    response = sync_get(search_url)

                    if response.status_code == 200:
                        html_content = response.text
                    else:
                        continue

                    # Parse HTML and extract relevant information
                    soup = BeautifulSoup(html_content, "html.parser")  # type: ignore
                    source_hits = self._extract_hits_from_html(
                        soup, source, query, search_url
                    )
                    hits.extend(source_hits)

                except Exception as e:
                    logger.warning(f"Scraping failed for URL {search_url}: {e}")
                    continue

            return hits

        except Exception as e:
            logger.error(f"Web scraping failed for {source.source_name}: {e}")
            return []

    async def _search_via_tor(
        self, source: IntelligenceSource, query: str
    ) -> List[CrossReferenceHit]:
        """Search source via Tor for anonymous access."""
        hits = []

        try:
            # Create Tor transport
            tor_transport = ProxiedTransport(proxy_url="socks5h://127.0.0.1:9050")

            # Construct search URL based on source
            search_urls = self._construct_search_urls(source, query)

            for search_url in search_urls:
                try:
                    # Use Tor proxy for the request
                    response = tor_transport.get(search_url, timeout=30)

                    if response.status_code == 200:
                        html_content = response.text
                    else:
                        continue

                    # Parse HTML and extract relevant information
                    soup = BeautifulSoup(html_content, "html.parser")  # type: ignore
                    source_hits = self._extract_hits_from_html(
                        soup, source, query, search_url
                    )
                    hits.extend(source_hits)

                except Exception as e:
                    logger.warning(f"Tor scraping failed for URL {search_url}: {e}")
                    continue

            return hits

        except Exception as e:
            logger.error(f"Tor-based search failed for {source.source_name}: {e}")
            return []

    def _construct_search_urls(
        self, source: IntelligenceSource, query: str
    ) -> List[str]:
        """Construct search URLs for different sources."""
        search_urls = []
        encoded_query = quote(query)

        try:
            if source.source_id == "wikileaks":
                search_urls = [
                    f"{source.base_url}/search/?q={encoded_query}",
                    f"{source.base_url}/plusd/cables/?q={encoded_query}",
                ]

            elif source.source_id == "cryptome":
                search_urls = [f"{source.base_url}/search.htm?q={encoded_query}"]

            elif source.source_id == "icij_offshoreleaks":
                search_urls = [f"{source.base_url}/search?q={encoded_query}"]

            elif source.source_id == "wikispooks":
                search_urls = [
                    f"{source.base_url}/wiki/Special:Search?search={encoded_query}"
                ]

            elif source.source_id == "archive_today":
                search_urls = [f"{source.base_url}/search/?q={encoded_query}"]

            else:
                # Generic search URL construction
                search_urls = [
                    f"{source.base_url}/search?q={encoded_query}",
                    f"{source.base_url}/?search={encoded_query}",
                ]

            return search_urls

        except Exception as e:
            logger.error(f"URL construction failed for {source.source_name}: {e}")
            return []

    def _extract_hits_from_html(
        self,
        soup: BeautifulSoup,
        source: IntelligenceSource,
        query: str,
        search_url: str,
    ) -> List[CrossReferenceHit]:
        """Extract intelligence hits from HTML content."""
        hits: List[CrossReferenceHit] = []

        try:
            # Source-specific parsing
            if source.source_id == "wikileaks":
                hits.extend(
                    self._parse_wikileaks_results(soup, source, query, search_url)
                )
            elif source.source_id in [
                "icij_offshoreleaks",
                "panama_papers",
                "paradise_papers",
                "pandora_papers",
            ]:
                hits.extend(self._parse_icij_results(soup, source, query, search_url))
            elif source.source_id == "wikispooks":
                hits.extend(
                    self._parse_wikispooks_results(soup, source, query, search_url)
                )
            elif source.source_id == "cryptome":
                hits.extend(
                    self._parse_cryptome_results(soup, source, query, search_url)
                )
            else:
                # Generic parsing for other sources
                hits.extend(
                    self._parse_generic_results(soup, source, query, search_url)
                )

            return hits

        except Exception as e:
            logger.error(f"HTML extraction failed: {e}")
            return []

    def _parse_generic_results(
        self,
        soup: BeautifulSoup,
        source: IntelligenceSource,
        query: str,
        search_url: str,
    ) -> List[CrossReferenceHit]:
        """Generic HTML parsing for search results."""
        hits = []

        try:
            # Look for common search result patterns
            result_selectors = [
                "div.search-result",
                "div.result",
                "article",
                "li.search-item",
                ".search-result",
                ".result-item",
            ]

            results = []
            for selector in result_selectors:
                results = soup.select(selector)  # type: ignore
                if results:
                    break

            if not results:
                # Fallback: look for links containing the query
                links = soup.find_all("a", href=True)  # type: ignore
                results = [
                    link for link in links if query.lower() in link.get_text().lower()
                ]  # type: ignore

            for result in results[:10]:  # Limit to top 10
                try:
                    # Extract title
                    title = "No title"
                    for tag in ["h1", "h2", "h3", "h4", "title"]:
                        title_elem = result.find(tag)  # type: ignore
                        if title_elem:
                            title = title_elem.get_text().strip()  # type: ignore
                            break
                    if title == "No title" and hasattr(result, "get_text"):
                        title = result.get_text().strip()[:100]  # type: ignore

                    # Extract URL
                    url = search_url
                    link_elem = result.find("a", href=True)  # type: ignore
                    if link_elem and "href" in link_elem.attrs:  # type: ignore
                        href = link_elem["href"]  # type: ignore
                        if isinstance(href, str):
                            url = href
                            if not url.startswith("http"):
                                url = f"{source.base_url.rstrip('/')}/{url.lstrip('/')}"

                    # Extract content snippet
                    content = title
                    for tag in ["p", "div", "span"]:
                        content_elem = result.find(tag)  # type: ignore
                        if content_elem:
                            content = content_elem.get_text().strip()  # type: ignore
                            break

                    # Calculate relevance
                    relevance = self._calculate_relevance(content, query)

                    if relevance > 0.1:  # Only include relevant results
                        hit = CrossReferenceHit(
                            hit_id=f"{source.source_id}_{hashlib.md5(url.encode()).hexdigest()[:8]}",
                            source=source.source_name,
                            title=title,
                            content=content,
                            url=url,
                            timestamp=datetime.now(),
                            confidence=0.7,
                            relevance_score=relevance,
                        )
                        hits.append(hit)

                except Exception:
                    continue

            return hits

        except Exception:
            logger.error("Generic parsing failed")
            return []

    def _parse_wikileaks_results(
        self,
        soup: BeautifulSoup,
        source: IntelligenceSource,
        query: str,
        search_url: str,
    ) -> List[CrossReferenceHit]:
        """Parse WikiLeaks search results."""
        hits = []

        try:
            # WikiLeaks search results are in div.result or similar
            results = soup.find_all("div", class_="result") or soup.find_all("article")  # type: ignore

            for result in results[:10]:
                try:
                    title_elem = result.find("h3") or result.find("a")  # type: ignore
                    title = (
                        title_elem.get_text().strip()
                        if title_elem
                        else "WikiLeaks Document"
                    )  # type: ignore

                    link_elem = result.find("a", href=True)  # type: ignore
                    url = link_elem["href"] if link_elem else search_url  # type: ignore

                    content_elem = result.find("p") or result  # type: ignore
                    content = content_elem.get_text().strip() if content_elem else ""  # type: ignore

                    relevance = self._calculate_relevance(content, query)

                    if relevance > 0.1:
                        hit = CrossReferenceHit(
                            hit_id=f"wikileaks_{hashlib.md5(url.encode()).hexdigest()[:8]}",  # type: ignore
                            source="WikiLeaks",
                            title=title,
                            content=content,
                            url=url,  # type: ignore
                            timestamp=datetime.now(),
                            confidence=0.9,
                            relevance_score=relevance,
                        )
                        hits.append(hit)

                except Exception:
                    continue

            return hits

        except Exception as e:
            logger.error(f"WikiLeaks parsing failed: {e}")
            return []

    def _parse_icij_results(
        self,
        soup: BeautifulSoup,
        source: IntelligenceSource,
        query: str,
        search_url: str,
    ) -> List[CrossReferenceHit]:
        """Parse ICIJ database results."""
        hits = []

        try:
            # ICIJ results are typically in cards or list items
            results = soup.find_all("div", class_=re.compile(r"card|result|item"))  # type: ignore

            for result in results[:10]:
                try:
                    title_elem = (
                        result.find("h3") or result.find("h4") or result.find("a")
                    )  # type: ignore
                    title = (
                        title_elem.get_text().strip() if title_elem else "ICIJ Document"
                    )  # type: ignore

                    link_elem = result.find("a", href=True)  # type: ignore
                    url = link_elem["href"] if link_elem else search_url  # type: ignore
                    if not url.startswith("http"):  # type: ignore
                        url = f"https://offshoreleaks.icij.org{url}"

                    content_elem = result.find("p") or result  # type: ignore
                    content = content_elem.get_text().strip() if content_elem else ""  # type: ignore

                    relevance = self._calculate_relevance(content, query)

                    if relevance > 0.1:
                        hit = CrossReferenceHit(
                            hit_id=f"icij_{hashlib.md5(url.encode()).hexdigest()[:8]}",  # type: ignore
                            source=source.source_name,
                            title=title,
                            content=content,
                            url=url,  # type: ignore
                            timestamp=datetime.now(),
                            confidence=0.95,
                            relevance_score=relevance,
                        )
                        hits.append(hit)

                except Exception:
                    continue

            return hits

        except Exception as e:
            logger.error(f"ICIJ parsing failed: {e}")
            return []

    def _parse_wikispooks_results(
        self,
        soup: BeautifulSoup,
        source: IntelligenceSource,
        query: str,
        search_url: str,
    ) -> List[CrossReferenceHit]:
        """Parse Wikispooks search results."""
        hits = []

        try:
            # Wikispooks uses MediaWiki search results
            results = soup.find_all("div", class_="mw-search-result") or soup.find_all(
                "li"
            )  # type: ignore

            for result in results[:10]:
                try:
                    title_elem = result.find("a")  # type: ignore
                    title = (
                        title_elem.get_text().strip()
                        if title_elem
                        else "Wikispooks Article"
                    )  # type: ignore

                    link_elem = result.find("a", href=True)  # type: ignore
                    url = link_elem["href"] if link_elem else search_url  # type: ignore
                    if not url.startswith("http"):  # type: ignore
                        url = f"https://wikispooks.com{url}"

                    content_elem = result.find("div", class_="searchresult") or result  # type: ignore
                    content = content_elem.get_text().strip() if content_elem else ""  # type: ignore

                    relevance = self._calculate_relevance(content, query)

                    if relevance > 0.1:
                        hit = CrossReferenceHit(
                            hit_id=f"wikispooks_{hashlib.md5(url.encode()).hexdigest()[:8]}",  # type: ignore
                            source="Wikispooks",
                            title=title,
                            content=content,
                            url=url,  # type: ignore
                            timestamp=datetime.now(),
                            confidence=0.7,
                            relevance_score=relevance,
                        )
                        hits.append(hit)

                except Exception:
                    continue

            return hits

        except Exception as e:
            logger.error(f"Wikispooks parsing failed: {e}")
            return []

    def _parse_cryptome_results(
        self,
        soup: BeautifulSoup,
        source: IntelligenceSource,
        query: str,
        search_url: str,
    ) -> List[CrossReferenceHit]:
        """Parse Cryptome search results."""
        hits = []

        try:
            # Cryptome has simple HTML structure
            links = soup.find_all("a", href=True)  # type: ignore

            for link in links[:20]:  # Check more links
                try:
                    url = link["href"]  # type: ignore
                    if not url.startswith("http"):  # type: ignore
                        url = f"https://cryptome.org{url}"

                    title = link.get_text().strip() or "Cryptome Document"  # type: ignore
                    content = title  # Cryptome often has descriptive link text

                    relevance = self._calculate_relevance(content, query)

                    if relevance > 0.2:  # Higher threshold for Cryptome
                        hit = CrossReferenceHit(
                            hit_id=f"cryptome_{hashlib.md5(url.encode()).hexdigest()[:8]}",  # type: ignore
                            source="Cryptome",
                            title=title,
                            content=content,
                            url=url,  # type: ignore
                            timestamp=datetime.now(),
                            confidence=0.8,
                            relevance_score=relevance,
                        )
                        hits.append(hit)

                except Exception:
                    continue

            return hits

        except Exception as e:
            logger.error(f"Cryptome parsing failed: {e}")
            return []

    def _calculate_relevance(self, content: str, query: str) -> float:
        """Calculate relevance score for content."""
        try:
            content_lower = content.lower()
            query_lower = query.lower()

            # Basic keyword matching
            query_words = query_lower.split()
            content_words = content_lower.split()

            matches = sum(1 for word in query_words if word in content_words)
            base_score = matches / len(query_words) if query_words else 0

            # Boost for exact phrase matches
            if query_lower in content_lower:
                base_score += 0.3

            # Boost for proximity of query terms
            if len(query_words) > 1:
                for i, word in enumerate(query_words[:-1]):
                    next_word = query_words[i + 1]
                    if word in content_lower and next_word in content_lower:
                        word_pos = content_lower.find(word)
                        next_pos = content_lower.find(next_word, word_pos)
                        if 0 < next_pos - word_pos < 100:  # Words within 100 characters
                            base_score += 0.1
            return base_score

        except Exception as e:
            logger.warning(f"Relevance calculation failed: {e}")
            return 0.0

    async def _enhance_hits_with_patterns(
        self, hits: List[CrossReferenceHit], query: str
    ) -> List[CrossReferenceHit]:
        """Enhance hits with pattern analysis and hidden indicator detection."""
        enhanced_hits = []

        try:
            for hit in hits:
                # Detect conspiracy patterns
                conspiracy_markers = self._detect_conspiracy_patterns(hit.content)
                hit.conspiracy_markers = conspiracy_markers

                # Detect hidden indicators
                hidden_indicators = self._detect_hidden_indicators(hit.content)
                hit.hidden_indicators = hidden_indicators

                # Use pattern engine for additional analysis
                pattern_input = {
                    "text": hit.content,
                    "content": hit.content,
                    "title": hit.title,
                    "source": hit.source,
                    "url": hit.url,
                    "timestamp": hit.timestamp.isoformat(),
                    "query": query,
                }
                patterns = self._get_pattern_engine().analyze_patterns(
                    str(pattern_input)
                )
                # Normalize patterns to a list of strings regardless of return type
                normalized_patterns: List[str] = []
                for p in patterns or []:
                    if hasattr(p, "pattern_type"):
                        normalized_patterns.append(str(getattr(p, "pattern_type")))
                    elif isinstance(p, dict) and "pattern_type" in p:
                        if isinstance(p, dict) and "pattern_type" in p:
                            normalized_patterns.append(str(p["pattern_type"]))
                    else:
                        normalized_patterns.append(str(p))
                hit.patterns_detected = normalized_patterns

                # Use LLM for enhanced analysis if available
                if self.llm_engine.active_backend:
                    try:
                        llm_analysis = await self._analyze_with_llm(
                            hit.content, "pattern_analysis"
                        )
                        if llm_analysis:
                            # Incorporate LLM insights
                            hit.hidden_indicators.extend(llm_analysis.insights)

                            # Update confidence based on LLM analysis
                            level_val = llm_analysis.risk_assessment.get("level", 0)
                            try:
                                level_num = float(level_val)
                            except Exception:
                                try:
                                    level_num = float(
                                        re.sub(r"[^\d.]+", "", str(level_val)) or 0.0
                                    )
                                except Exception:
                                    level_num = 0.0
                            if level_num > 5:
                                hit.confidence = min(hit.confidence + 0.1, 1.0)

                    except Exception as e:
                        logger.warning(f"LLM analysis failed for hit {hit.hit_id}: {e}")

                enhanced_hits.append(hit)

            return enhanced_hits

        except Exception as e:
            logger.error(f"Hit enhancement failed: {e}")
            return hits

    async def _analyze_with_llm(
        self, text: str, mode: str
    ) -> Optional["LLMAnalysisResult"]:
        """Adapter that probes LocalLLMEngine for an analysis method and normalizes the result."""
        try:
            method = None
            for name in (
                "analyze_osint_data",
                "analyze_text",
                "analyze",
                "run",
                "infer",
            ):
                candidate = getattr(self.llm_engine, name, None)
                if candidate:
                    method = candidate
                    break
            if not method:
                return None

            result = method(text, mode)
            if asyncio.iscoroutine(result):
                result = await result

            insights: List[str] = []
            risk_assessment: Dict[str, Any] = {}

            if result is None:
                pass
            elif hasattr(result, "insights") or hasattr(result, "risk_assessment"):
                insights = list(getattr(result, "insights", []) or [])
                risk_assessment = dict(getattr(result, "risk_assessment", {}) or {})
            elif isinstance(result, dict):
                raw_insights = result.get("insights", [])
                raw_risk = result.get("risk_assessment", result.get("risk", {}))
                if isinstance(raw_insights, list):
                    insights = [str(i) for i in raw_insights]
                elif raw_insights:
                    insights = [str(raw_insights)]
                if isinstance(raw_risk, dict):
                    risk_assessment = raw_risk
                elif raw_risk is not None:
                    risk_assessment = {"level": raw_risk}
            else:
                insights = [str(result)]

            return LLMAnalysisResult(insights=insights, risk_assessment=risk_assessment)

        except Exception as e:
            logger.warning(f"LLM adapter failed: {e}")
            return None

    def _detect_conspiracy_patterns(self, content: str) -> List[str]:
        """Detect conspiracy theory patterns in content."""
        markers = []

        try:
            content_lower = content.lower()

            for pattern_type, patterns in self.conspiracy_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content_lower, re.IGNORECASE)
                    if matches:
                        markers.append(f"{pattern_type}: {', '.join(matches)}")

            return markers

        except Exception as e:
            logger.warning(f"Conspiracy pattern detection failed: {e}")
            return []

    def _detect_hidden_indicators(self, content: str) -> List[str]:
        """Detect hidden indicators that most analysts miss."""
        indicators = []

        try:
            content_lower = content.lower()

            # Financial indicator patterns
            financial_patterns = [
                r"\$[\d,]+\.?\d*\s*(million|billion|thousand)",
                r"offshore\s+account",
                r"shell\s+company",
                r"money\s+laundering",
                r"suspicious\s+transactions?",
            ]

            for pattern in financial_patterns:
                matches = re.findall(pattern, content_lower, re.IGNORECASE)
                if matches:
                    indicators.append(f"Financial: {', '.join(matches)}")

            # Timing indicators
            timing_patterns = [
                r"just\s+before",
                r"immediately\s+after",
                r"coincidentally",
                r"same\s+time",
                r"suspicious\s+timing",
            ]

            for pattern in timing_patterns:
                matches = re.findall(pattern, content_lower, re.IGNORECASE)
                if matches:
                    indicators.append(f"Timing: {', '.join(matches)}")

            # Relationship indicators
            relationship_patterns = [
                r"undisclosed\s+relationship",
                r"family\s+connection",
                r"business\s+partner",
                r"board\s+member",
                r"advisor\s+to",
            ]

            for pattern in relationship_patterns:
                matches = re.findall(pattern, content_lower, re.IGNORECASE)
                if matches:
                    indicators.append(f"Relationship: {', '.join(matches)}")

            return indicators

        except Exception as e:
            logger.warning(f"Hidden indicator detection failed: {e}")
            return []

    def _rank_hits_by_relevance(
        self, hits: List[CrossReferenceHit], query: str, search_mode: str
    ) -> List[CrossReferenceHit]:
        """Rank hits by relevance and search mode preferences."""
        try:
            for hit in hits:
                # Base score from relevance and confidence
                score = hit.relevance_score * hit.confidence

                # Mode-specific boosts
                if search_mode == "conspiracy_focus":
                    score += len(hit.conspiracy_markers) * 0.1
                elif search_mode == "crime_focus":
                    crime_keywords = [
                        "money laundering",
                        "corruption",
                        "organized crime",
                        "trafficking",
                    ]
                    crime_matches = sum(
                        1
                        for keyword in crime_keywords
                        if keyword in hit.content.lower()
                    )
                    score += crime_matches * 0.15
                elif search_mode == "hidden_patterns":
                    score += len(hit.hidden_indicators) * 0.1

                # Boost for pattern detection
                score += len(hit.patterns_detected) * 0.05

                # Boost for credible sources
                credible_sources = [
                    "wikileaks",
                    "icij",
                    "panama papers",
                    "paradise papers",
                ]
                if any(source in hit.source.lower() for source in credible_sources):
                    score += 0.2

                hit.relevance_score = min(score, 1.0)

            # Sort by relevance score (descending)
            hits.sort(key=lambda x: x.relevance_score, reverse=True)

            return hits

        except Exception as e:
            logger.error(f"Hit ranking failed: {e}")
            return hits

    async def analyze_conspiracy_theory(
        self, theory: ConspiracyTheory
    ) -> Dict[str, Any]:
        """
        Analyze a conspiracy theory by examining every angle to seek truth.

        This method specifically looks for:
        - Evidence supporting or refuting key claims
        - Hidden connections and patterns
        - Plausible deniability layers
        - Disinformation markers vs truth indicators
        """
        analysis: Dict[str, Any] = {
            "theory_id": theory.theory_id,
            "plausibility_assessment": {},
            "evidence_analysis": {},
            "hidden_patterns": {},
            "truth_indicators": [],
            "disinformation_markers": [],
            "recommendations": [],
            "confidence_score": 0.0,
        }

        try:
            # Search for evidence related to each key claim
            for claim in theory.key_claims:
                claim_evidence = await self.cross_reference_search(
                    claim, search_mode="conspiracy_focus"
                )

                # Analyze evidence for truth vs disinformation
                claim_analysis = await self._analyze_claim_evidence(
                    claim, claim_evidence
                )
                analysis["evidence_analysis"][claim] = claim_analysis

            # Search for connections between key actors
            actor_connections = await self._analyze_actor_connections(theory.key_actors)
            analysis["hidden_patterns"]["actor_connections"] = actor_connections

            # Analyze key events for patterns
            event_patterns = await self._analyze_event_patterns(theory.key_events)
            analysis["hidden_patterns"]["event_patterns"] = event_patterns

            # Use LLM for comprehensive analysis
            if self.llm_engine.active_backend:
                llm_analysis = await self._llm_conspiracy_analysis(theory)
                analysis["llm_insights"] = llm_analysis

            # Calculate overall plausibility
            analysis["plausibility_assessment"] = self._calculate_theory_plausibility(
                theory, analysis
            )

            # Generate investigation recommendations
            analysis["recommendations"] = self._generate_investigation_recommendations(
                theory, analysis
            )

            return analysis

        except Exception as e:
            logger.error(f"Conspiracy theory analysis failed: {e}")
            return analysis

    async def _analyze_claim_evidence(
        self, claim: str, evidence: List[CrossReferenceHit]
    ) -> Dict[str, Any]:
        """Analyze evidence for a specific claim."""
        claim_analysis: Dict[str, Any] = {
            "claim": claim,
            "supporting_evidence": [],
            "contradicting_evidence": [],
            "neutral_evidence": [],
            "truth_score": 0.0,
            "disinformation_score": 0.0,
        }

        try:
            for hit in evidence:
                # Classify evidence as supporting, contradicting, or neutral
                classification = self._classify_evidence(claim, hit)

                if classification == "supporting":
                    claim_analysis["supporting_evidence"].append(hit)
                elif classification == "contradicting":
                    claim_analysis["contradicting_evidence"].append(hit)
                else:
                    claim_analysis["neutral_evidence"].append(hit)

            # Calculate truth vs disinformation scores
            support_score = len(claim_analysis["supporting_evidence"])
            contradict_score = len(claim_analysis["contradicting_evidence"])

            total_evidence = support_score + contradict_score
            if total_evidence > 0:
                claim_analysis["truth_score"] = support_score / total_evidence
                claim_analysis["disinformation_score"] = (
                    contradict_score / total_evidence
                )

            return claim_analysis

        except Exception as e:
            logger.error(f"Claim evidence analysis failed: {e}")
            return claim_analysis

    def _classify_evidence(self, claim: str, hit: CrossReferenceHit) -> str:
        """Classify evidence as supporting, contradicting, or neutral."""
        try:
            content_lower = hit.content.lower()
            claim_lower = claim.lower()

            # Look for explicit support/contradiction keywords
            support_keywords = [
                "confirms",
                "proves",
                "shows",
                "demonstrates",
                "evidence of",
            ]
            contradict_keywords = [
                "debunks",
                "disproves",
                "false",
                "incorrect",
                "no evidence",
            ]

            support_score = sum(
                1 for keyword in support_keywords if keyword in content_lower
            )
            contradict_score = sum(
                1 for keyword in contradict_keywords if keyword in content_lower
            )

            # Check for claim keywords in content
            claim_words = claim_lower.split()
            claim_presence = sum(1 for word in claim_words if word in content_lower)

            if claim_presence >= len(claim_words) * 0.7:  # Most claim words present
                if support_score > contradict_score:
                    return "supporting"
                elif contradict_score > support_score:
                    return "contradicting"

            return "neutral"

        except Exception as e:
            logger.warning(f"Evidence classification failed: {e}")
            return "neutral"

    async def _analyze_actor_connections(self, actors: List[str]) -> Dict[str, Any]:
        """Analyze connections between key actors."""
        connections: Dict[str, Any] = {
            "direct_connections": [],
            "indirect_connections": [],
            "network_analysis": {},
            "hidden_relationships": [],
        }

        try:
            # Search for each pair of actors
            for i, actor1 in enumerate(actors):
                for actor2 in actors[i + 1 :]:
                    # Search for both actors together
                    connection_query = f'"{actor1}" AND "{actor2}"'
                    connection_hits = await self.cross_reference_search(
                        connection_query, search_mode="hidden_patterns"
                    )

                    if connection_hits:
                        connections["direct_connections"].append(
                            {
                                "actor1": actor1,
                                "actor2": actor2,
                                "evidence": connection_hits[:3],  # Top 3 hits
                                "strength": len(connection_hits),
                            }
                        )

            # Look for intermediary connections
            for actor in actors:
                intermediary_hits = await self.cross_reference_search(
                    f'"{actor}" connected to', search_mode="hidden_patterns"
                )

                # Extract potential intermediaries
                for hit in intermediary_hits[:5]:
                    intermediaries = self._extract_potential_intermediaries(
                        hit.content, actors
                    )
                    if intermediaries:
                        connections["indirect_connections"].append(
                            {
                                "actor": actor,
                                "intermediaries": intermediaries,
                                "evidence": hit,
                            }
                        )

            return connections

        except Exception as e:
            logger.error(f"Actor connection analysis failed: {e}")
            return connections

    def _extract_potential_intermediaries(
        self, content: str, known_actors: List[str]
    ) -> List[str]:
        """Extract potential intermediary actors from content."""
        intermediaries = []

        try:
            # Look for patterns indicating intermediary relationships
            intermediary_patterns = [
                r"through\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
                r"via\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
                r"connected\s+to\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
                r"business\s+partner\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
                r"advisor\s+([A-Z][a-z]+\s+[A-Z][a-z]+)",
            ]

            for pattern in intermediary_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if match not in known_actors and len(match.split()) >= 2:
                        intermediaries.append(match)

            return list(set(intermediaries))  # Remove duplicates

        except Exception as e:
            logger.warning(f"Intermediary extraction failed: {e}")
            return []

    async def _analyze_event_patterns(self, events: List[str]) -> Dict[str, Any]:
        """Analyze patterns in key events."""
        patterns: Dict[str, Any] = {
            "temporal_patterns": [],
            "geographic_patterns": [],
            "causal_relationships": [],
            "suspicious_timing": [],
        }

        try:
            # Search for each event
            event_data = {}
            for event in events:
                event_hits = await self.cross_reference_search(
                    event, search_mode="hidden_patterns"
                )
                event_data[event] = event_hits

            # Analyze temporal patterns
            patterns["temporal_patterns"] = self._analyze_temporal_patterns(event_data)

            # Analyze geographic patterns
            patterns["geographic_patterns"] = self._analyze_geographic_patterns(
                event_data
            )

            # Look for causal relationships
            patterns["causal_relationships"] = self._analyze_causal_relationships(
                event_data
            )

            return patterns

        except Exception as e:
            logger.error(f"Event pattern analysis failed: {e}")
            return patterns

    def _analyze_temporal_patterns(
        self, event_data: Dict[str, List[CrossReferenceHit]]
    ) -> List[Dict[str, Any]]:
        """Analyze temporal patterns in events."""
        temporal_patterns = []

        try:
            # Extract dates and times from event evidence
            event_times = {}

            for event, hits in event_data.items():
                times = []
                for hit in hits:
                    # Extract dates from content using regex
                    date_patterns = [
                        r"\b(\d{1,2}/\d{1,2}/\d{2,4})\b",
                        r"\b(\d{4}-\d{2}-\d{2})\b",
                        r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b",
                    ]

                    for pattern in date_patterns:
                        dates = re.findall(pattern, hit.content, re.IGNORECASE)
                        times.extend(dates)

                event_times[event] = times

            # Look for suspicious timing patterns
            for event1, times1 in event_times.items():
                for event2, times2 in event_times.items():
                    if event1 != event2 and times1 and times2:
                        # Check for events happening close in time
                        temporal_patterns.append(
                            {
                                "event1": event1,
                                "event2": event2,
                                "pattern_type": "proximity",
                                "evidence": f"Events occurred around similar times: {times1[:2]} and {times2[:2]}",
                            }
                        )

            return temporal_patterns

        except Exception as e:
            logger.warning(f"Temporal pattern analysis failed: {e}")
            return []

    def _analyze_geographic_patterns(
        self, event_data: Dict[str, List[CrossReferenceHit]]
    ) -> List[Dict[str, Any]]:
        """Analyze geographic patterns in events."""
        geographic_patterns = []

        try:
            # Extract locations from event evidence
            event_locations = {}

            # Common location patterns
            location_patterns = [
                r"\b([A-Z][a-z]+,\s*[A-Z][A-Z])\b",  # City, State
                r"\b([A-Z][a-z]+,\s*[A-Z][a-z]+)\b",  # City, Country
                r"\b(New York|Los Angeles|London|Paris|Moscow|Beijing|Tokyo|Berlin|Rome|Madrid)\b",
            ]

            for event, hits in event_data.items():
                locations = []
                for hit in hits:
                    for pattern in location_patterns:
                        places = re.findall(pattern, hit.content)
                        locations.extend(places)

                event_locations[event] = list(set(locations))  # Remove duplicates

            # Look for geographic clustering
            all_locations = []
            for locations in event_locations.values():
                all_locations.extend(locations)

            location_counts: Dict[str, int] = {}
            for location in all_locations:
                location_counts[location] = location_counts.get(location, 0) + 1

            # Identify locations appearing in multiple events
            common_locations = {
                loc: count for loc, count in location_counts.items() if count > 1
            }

            if common_locations:
                for location, count in common_locations.items():
                    geographic_patterns.append(
                        {
                            "location": location,
                            "frequency": count,
                            "events": [
                                event
                                for event, locs in event_locations.items()
                                if location in locs
                            ],
                            "significance": "High" if count > 2 else "Medium",
                        }
                    )

            return geographic_patterns

        except Exception as e:
            logger.warning(f"Geographic pattern analysis failed: {e}")
            return []

    def _analyze_causal_relationships(
        self, event_data: Dict[str, List[CrossReferenceHit]]
    ) -> List[Dict[str, Any]]:
        """Analyze causal relationships between events."""
        causal_relationships = []

        try:
            # Causal indicators that suggest one event caused another
            causal_indicators = [
                "led to",
                "caused",
                "resulted in",
                "triggered",
                "sparked",
                "provoked",
                "precipitated",
                "brought about",
                "gave rise to",
                "culminated in",
                "stemmed from",
                "arose from",
                "originated from",
            ]

            # Check each pair of events for causal relationships
            events = list(event_data.keys())
            for i, event1 in enumerate(events):
                for event2 in events[i + 1 :]:
                    # Search for evidence of causality
                    causal_evidence = []
                    for hit in event_data[event1] + event_data[event2]:
                        content_lower = hit.content.lower()
                        for indicator in causal_indicators:
                            if indicator in content_lower:
                                causal_evidence.append(hit)
                                break

                    if causal_evidence:
                        causal_relationships.append(
                            {
                                "cause_event": event1,
                                "effect_event": event2,
                                "evidence": causal_evidence[
                                    :3
                                ],  # Top 3 pieces of evidence
                                "strength": len(causal_evidence),
                                "indicators_found": causal_indicators,
                            }
                        )

            return causal_relationships

        except Exception as e:
            logger.warning(f"Causal relationship analysis failed: {e}")
            return []

    def _calculate_theory_plausibility(
        self, theory: ConspiracyTheory, analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate overall plausibility score for conspiracy theory."""
        try:
            # Factors affecting plausibility
            evidence_score = 0.0
            actor_connection_score = 0.0
            event_pattern_score = 0.0
            source_credibility_score = 0.0

            # Analyze evidence quality
            if "evidence_analysis" in analysis:
                supporting_count = 0
                contradicting_count = 0

                for claim_analysis in analysis["evidence_analysis"].values():
                    supporting_count += len(
                        claim_analysis.get("supporting_evidence", [])
                    )
                    contradicting_count += len(
                        claim_analysis.get("contradicting_evidence", [])
                    )

                total_evidence = supporting_count + contradicting_count
                if total_evidence > 0:
                    evidence_score = supporting_count / total_evidence

            # Analyze actor connections
            if (
                "hidden_patterns" in analysis
                and "actor_connections" in analysis["hidden_patterns"]
            ):
                connections = analysis["hidden_patterns"]["actor_connections"]
                direct_connections = len(connections.get("direct_connections", []))
                indirect_connections = len(connections.get("indirect_connections", []))

                # More connections increase plausibility
                actor_connection_score = min(
                    (direct_connections * 0.3 + indirect_connections * 0.1), 1.0
                )

            # Analyze event patterns
            if (
                "hidden_patterns" in analysis
                and "event_patterns" in analysis["hidden_patterns"]
            ):
                patterns = analysis["hidden_patterns"]["event_patterns"]
                temporal_patterns = len(patterns.get("temporal_patterns", []))
                causal_patterns = len(patterns.get("causal_relationships", []))

                event_pattern_score = min(
                    (temporal_patterns * 0.2 + causal_patterns * 0.3), 1.0
                )

            # Calculate weighted overall score
            weights = {
                "evidence": 0.4,
                "connections": 0.3,
                "patterns": 0.2,
                "credibility": 0.1,
            }

            overall_score = (
                evidence_score * weights["evidence"]
                + actor_connection_score * weights["connections"]
                + event_pattern_score * weights["patterns"]
                + source_credibility_score * weights["credibility"]
            )

            # Determine plausibility category
            if overall_score >= 0.7:
                category = "High Plausibility"
            elif overall_score >= 0.4:
                category = "Moderate Plausibility"
            else:
                category = "Low Plausibility"

            return {
                "overall_score": overall_score,
                "category": category,
                "evidence_score": evidence_score,
                "connection_score": actor_connection_score,
                "pattern_score": event_pattern_score,
                "component_scores": {
                    "evidence_quality": evidence_score,
                    "actor_connections": actor_connection_score,
                    "event_patterns": event_pattern_score,
                    "source_credibility": source_credibility_score,
                },
            }

        except Exception as e:
            logger.error(f"Plausibility calculation failed: {e}")
            return {"overall_score": 0.0, "category": "Unable to assess"}

    def _generate_investigation_recommendations(
        self, theory: ConspiracyTheory, analysis: Dict[str, Any]
    ) -> List[str]:
        """Generate specific investigation recommendations."""
        recommendations = []

        try:
            # Evidence-based recommendations
            if "evidence_analysis" in analysis:
                for claim, claim_analysis in analysis["evidence_analysis"].items():
                    if len(claim_analysis.get("supporting_evidence", [])) < 2:
                        recommendations.append(
                            f"Seek additional evidence for claim: '{claim}'"
                        )

                    if claim_analysis.get("truth_score", 0) < 0.3:
                        recommendations.append(
                            f"Investigate contradictory evidence for: '{claim}'"
                        )

            # Connection-based recommendations
            if "hidden_patterns" in analysis:
                connections = analysis["hidden_patterns"].get("actor_connections", {})
                if (
                    len(connections.get("direct_connections", []))
                    < len(theory.key_actors) / 2
                ):
                    recommendations.append(
                        "Investigate missing connections between key actors"
                    )

                if connections.get("indirect_connections"):
                    recommendations.append(
                        "Follow up on intermediary connections and shell entities"
                    )

            # Pattern-based recommendations
            patterns = analysis.get("hidden_patterns", {}).get("event_patterns", {})
            if patterns.get("temporal_patterns"):
                recommendations.append(
                    "Investigate suspicious timing correlations between events"
                )

            if patterns.get("geographic_patterns"):
                recommendations.append("Analyze geographic clustering of activities")

            # Source diversification
            recommendations.append(
                "Expand source coverage to include government archives and court records"
            )
            recommendations.append(
                "Cross-reference with financial transaction databases"
            )
            recommendations.append(
                "Investigate social media and communication patterns"
            )

            # Deep investigation angles
            recommendations.extend(
                [
                    "Analyze beneficial ownership structures and shell company networks",
                    "Investigate family and personal relationships between key actors",
                    "Look for patterns in timing of business registrations and dissolusions",
                    "Examine travel records and geographic movement patterns",
                    "Investigate communication metadata and timing patterns",
                    "Analyze financial flows and unusual transaction patterns",
                    "Look for regulatory capture and revolving door relationships",
                ]
            )

            return recommendations

        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            return ["Conduct comprehensive multi-source investigation"]

    async def _llm_conspiracy_analysis(
        self, theory: ConspiracyTheory
    ) -> Dict[str, Any]:
        """Use LLM to perform comprehensive conspiracy theory analysis."""
        llm_analysis: Dict[str, Any] = {
            "llm_summary": "",
            "key_insights": [],
            "plausibility_assessment": "",
            "missing_evidence": [],
            "alternative_explanations": [],
            "investigation_priorities": [],
        }

        try:
            if not self.llm_engine or not self.llm_engine.active_backend:
                return llm_analysis

            # Create comprehensive analysis prompt
            analysis_prompt = f"""
            Analyze the following conspiracy theory comprehensively:

            Theory: {theory.title}
            Description: {theory.description}

            Key Claims:
            {chr(10).join(f"- {claim}" for claim in theory.key_claims)}

            Key Actors:
            {chr(10).join(f"- {actor}" for actor in theory.key_actors)}

            Key Events:
            {chr(10).join(f"- {event}" for event in theory.key_events)}

            Please provide:
            1. A summary of the theory's plausibility
            2. Key insights about connections between actors and events
            3. Assessment of what evidence would be needed to prove/disprove the theory
            4. Alternative explanations for the observed patterns
            5. Investigation priorities and recommendations

            Focus on logical analysis, evidence requirements, and investigative approaches.
            """

            # Get LLM analysis using dynamic method access
            analyze_method = getattr(self.llm_engine, "analyze_intelligence", None)
            if analyze_method:
                llm_response = await analyze_method(
                    {
                        "type": "conspiracy_analysis",
                        "theory": {
                            "title": theory.title,
                            "description": theory.description,
                            "key_claims": theory.key_claims,
                            "key_actors": theory.key_actors,
                            "key_events": theory.key_events,
                        },
                        "analysis_prompt": analysis_prompt,
                    }
                )
            else:
                llm_response = None

            # Parse LLM response into structured format
            if isinstance(llm_response, dict):
                llm_analysis["llm_summary"] = llm_response.get("analysis", "")
                llm_analysis["key_insights"] = llm_response.get("insights", [])
                llm_analysis["plausibility_assessment"] = llm_response.get(
                    "assessment", ""
                )
                llm_analysis["missing_evidence"] = llm_response.get(
                    "missing_evidence", []
                )
                llm_analysis["alternative_explanations"] = llm_response.get(
                    "alternatives", []
                )
                llm_analysis["investigation_priorities"] = llm_response.get(
                    "priorities", []
                )
            elif isinstance(llm_response, str):
                llm_analysis["llm_summary"] = llm_response

                # Extract key insights from response
                lines = llm_response.split("\n")
                current_section = ""

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Identify sections
                    if any(
                        keyword in line.lower()
                        for keyword in ["summary", "plausibility", "assessment"]
                    ):
                        current_section = "summary"
                        llm_analysis["plausibility_assessment"] = line
                    elif any(
                        keyword in line.lower()
                        for keyword in ["insight", "connection", "key finding"]
                    ):
                        current_section = "insights"
                        llm_analysis["key_insights"].append(line)
                    elif any(
                        keyword in line.lower()
                        for keyword in ["evidence", "missing", "needed"]
                    ):
                        current_section = "evidence"
                        llm_analysis["missing_evidence"].append(line)
                    elif any(
                        keyword in line.lower()
                        for keyword in ["alternative", "explanation"]
                    ):
                        current_section = "alternatives"
                        llm_analysis["alternative_explanations"].append(line)
                    elif any(
                        keyword in line.lower()
                        for keyword in ["priority", "recommend", "investigat"]
                    ):
                        current_section = "priorities"
                        llm_analysis["investigation_priorities"].append(line)
                    elif current_section and line.startswith(("-", "•", "*")):
                        # Add to current section
                        if current_section == "insights":
                            llm_analysis["key_insights"].append(line[1:].strip())
                        elif current_section == "evidence":
                            llm_analysis["missing_evidence"].append(line[1:].strip())
                        elif current_section == "alternatives":
                            llm_analysis["alternative_explanations"].append(
                                line[1:].strip()
                            )
                        elif current_section == "priorities":
                            llm_analysis["investigation_priorities"].append(
                                line[1:].strip()
                            )

            return llm_analysis

        except Exception as e:
            logger.error(f"LLM conspiracy analysis failed: {e}")
            return llm_analysis


# Factory function
def create_cross_reference_engine() -> CrossReferenceEngine:
    """Create and initialize cross-reference intelligence engine."""
    return CrossReferenceEngine()


# Example usage
if __name__ == "__main__":

    async def demo():
        """Demonstrate cross-reference engine capabilities."""
        engine = create_cross_reference_engine()

        print("Cross-Reference Intelligence Engine Demo")
        print("=======================================")

        # Example search
        query = "Panama Papers shell company"
        hits = await engine.cross_reference_search(query, search_mode="crime_focus")

        print(f"\nFound {len(hits)} cross-reference hits:")
        for hit in hits[:3]:
            print(f"- {hit.source}: {hit.title}")
            print(
                f"  Relevance: {hit.relevance_score:.2f}, Confidence: {hit.confidence:.2f}"
            )
            print(f"  Hidden indicators: {len(hit.hidden_indicators)}")
            print()

        # Example conspiracy theory analysis
        theory = ConspiracyTheory(
            theory_id="example_001",
            title="Offshore Financial Network",
            description="Investigation into offshore financial networks",
            key_claims=["Shell companies used for money laundering"],
            key_actors=["Mossack Fonseca", "Various politicians"],
            key_events=["Panama Papers leak", "Paradise Papers leak"],
        )

        analysis = await engine.analyze_conspiracy_theory(theory)
        print(
            f"Theory plausibility: {analysis['plausibility_assessment'].get('category', 'Unknown')}"
        )

    asyncio.run(demo())
