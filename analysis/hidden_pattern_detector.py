"""
Hidden Pattern Detection Framework
=================================

Advanced pattern analysis system designed to detect hidden connections,
plausible deniability layers, and sophisticated patterns that most analysts miss.

This framework specializes in:
- Truth-seeking through multi-dimensional pattern analysis
- Detecting deliberate obfuscation and misdirection
- Uncovering hidden networks and shell structures
- Identifying temporal, geographic, and behavioral anomalies
- Penetrating layers of plausible deniability
- Correlation analysis across seemingly unrelated data points
"""

import asyncio
import logging
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import networkx as nx
# Import our existing modules
from analysis.cross_reference_engine import CrossReferenceEngine, CrossReferenceHit
from core.local_llm_engine import create_local_llm_engine

# Avoid circular imports - use lazy loading if needed

logger = logging.getLogger(__name__)


@dataclass
class HiddenPattern:
    """Represents a detected hidden pattern."""

    pattern_id: str
    pattern_type: str
    pattern_name: str
    description: str
    confidence_score: float
    significance_level: float
    evidence: List[Any] = field(default_factory=list)
    entities_involved: List[str] = field(default_factory=list)
    temporal_markers: List[datetime] = field(default_factory=list)
    geographic_markers: List[str] = field(default_factory=list)
    obfuscation_indicators: List[str] = field(default_factory=list)
    truth_probability: float = 0.5
    analyst_notes: str = ""


@dataclass
class EntityRelationship:
    """Represents a relationship between entities."""

    entity1: str
    entity2: str
    relationship_type: str
    strength: float
    evidence: List[str] = field(default_factory=list)
    hidden_indicators: List[str] = field(default_factory=list)
    obfuscation_level: int = 0  # 0 = direct, 5 = highly obfuscated


@dataclass
class TemporalAnomaly:
    """Represents a temporal anomaly pattern."""

    anomaly_id: str
    events: List[Dict[str, Any]]
    time_window: timedelta
    anomaly_type: str  # synchronous, sequential, cyclical, suspicious_timing
    probability_score: float
    explanation: str


@dataclass
class NetworkStructure:
    """Represents a detected network structure."""

    structure_id: str
    structure_type: str  # shell_network, proxy_chain, cutout_structure
    core_entities: List[str]
    peripheral_entities: List[str]
    connection_layers: int
    obfuscation_score: float
    purpose_indicators: List[str] = field(default_factory=list)


class HiddenPatternDetector:
    """
    Advanced hidden pattern detection framework for sophisticated OSINT analysis.

    This detector specializes in finding patterns that are deliberately hidden,
    obfuscated, or disguised through layers of plausible deniability.
    """

    def __init__(self):
        self.cross_ref_engine = CrossReferenceEngine()
        self.llm_engine = create_local_llm_engine()
        self.pattern_engine = None  # Lazy load to avoid circular imports

        # Initialize detection algorithms
        self.detection_algorithms: Dict[str, Dict[str, Any]] = {}
        self._initialize_algorithms()

        # Initialize pattern libraries
        self.obfuscation_patterns: Dict[str, List[str]] = {}
        self.truth_indicators: Dict[str, List[str]] = {}
        self.truth_algorithms: Dict[str, Dict[str, Any]] = {}
        self._initialize_pattern_libraries()

        # Initialize truth-seeking algorithms
        self._initialize_truth_algorithms()

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
                        async def analyze(self, *args, **kwargs):
                            return {}
                        active = False
                    self.pattern_engine = NoOpPatternEngine()
        return self.pattern_engine

    def _initialize_algorithms(self):
        """Initialize sophisticated detection algorithms."""

        self.detection_algorithms = {
            "temporal_correlation": {
                "description": "Detect suspicious temporal correlations",
                "sensitivity": 0.85,
                "window_sizes": [
                    timedelta(hours=1),
                    timedelta(days=1),
                    timedelta(days=7),
                    timedelta(days=30),
                ],
            },
            "geographic_clustering": {
                "description": "Detect unusual geographic patterns",
                "cluster_threshold": 0.3,
                "min_samples": 2,
                "distance_metric": "haversine",
            },
            "entity_network_analysis": {
                "description": "Analyze hidden entity relationships",
                "centrality_measures": ["betweenness", "closeness", "eigenvector"],
                "community_detection": True,
                "shell_detection": True,
            },
            "linguistic_analysis": {
                "description": "Detect linguistic patterns and deception markers",
                "deception_indicators": True,
                "euphemism_detection": True,
                "code_word_analysis": True,
            },
            "financial_flow_analysis": {
                "description": "Analyze financial flows and laundering patterns",
                "layering_detection": True,
                "structuring_detection": True,
                "unusual_patterns": True,
            },
            "behavioral_anomaly_detection": {
                "description": "Detect anomalous behavioral patterns",
                "baseline_establishment": True,
                "deviation_analysis": True,
                "pattern_breaks": True,
            },
            "misdirection_analysis": {
                "description": "Detect deliberate misdirection and distraction",
                "red_herring_detection": True,
                "information_overload_analysis": True,
                "timing_manipulation": True,
            },
            "correlation_analysis": {
                "description": "Analyze correlations between different data dimensions",
                "cross_domain_correlations": True,
                "causality_detection": True,
                "association_mining": True,
                "minimum_support": 0.1,
                "minimum_confidence": 0.5,
            },
        }

    def _initialize_pattern_libraries(self):
        """Initialize comprehensive pattern libraries for detection."""

        self.obfuscation_patterns = {
            "shell_company_indicators": [
                r"registered\s+agent",
                r"nominee\s+director",
                r"shelf\s+company",
                r"mailbox\s+address",
                r"single\s+purpose\s+vehicle",
                r"special\s+purpose\s+entity",
                r"brass\s+plate\s+company",
                r"paper\s+company",
            ],
            "proxy_indicators": [
                r"acting\s+on\s+behalf",
                r"beneficial\s+owner",
                r"ultimate\s+beneficial\s+owner",
                r"proxy\s+holder",
                r"nominee\s+shareholder",
                r"trustee\s+arrangement",
                r"fiduciary\s+capacity",
                r"agent\s+for\s+undisclosed\s+principal",
            ],
            "timing_manipulation": [
                r"just\s+before\s+the\s+deadline",
                r"friday\s+afternoon\s+news\s+dump",
                r"holiday\s+announcement",
                r"after\s+market\s+close",
                r"during\s+major\s+distraction",
                r"convenient\s+timing",
                r"suspicious\s+coincidence",
            ],
            "linguistic_evasion": [
                r"consulting\s+services",
                r"advisory\s+capacity",
                r"strategic\s+partnership",
                r"business\s+development",
                r"commercial\s+arrangement",
                r"mutually\s+beneficial",
                r"arm\'s\s+length\s+transaction",
                r"normal\s+course\s+of\s+business",
            ],
            "misdirection_tactics": [
                r"unrelated\s+to\s+the\s+main\s+issue",
                r"red\s+herring",
                r"false\s+flag",
                r"distraction\s+campaign",
                r"smokescreen",
                r"diversionary\s+tactic",
                r"straw\s+man\s+argument",
                r"whataboutism",
            ],
        }

        self.truth_indicators = {
            "documentary_evidence": [
                r"official\s+records",
                r"court\s+documents",
                r"legal\s+filing",
                r"government\s+document",
                r"regulatory\s+filing",
                r"audited\s+financial\s+statements",
                r"sworn\s+testimony",
                r"under\s+oath",
            ],
            "verification_markers": [
                r"independently\s+verified",
                r"cross-referenced",
                r"corroborated\s+by",
                r"confirmed\s+by\s+multiple\s+sources",
                r"documented\s+evidence",
                r"forensic\s+analysis",
                r"expert\s+verification",
                r"third-party\s+validation",
            ],
            "transparency_indicators": [
                r"publicly\s+disclosed",
                r"transparent\s+process",
                r"open\s+records",
                r"freedom\s+of\s+information",
                r"public\s+registry",
                r"disclosed\s+in\s+filings",
                r"matter\s+of\s+public\s+record",
            ],
        }

    def _initialize_truth_algorithms(self):
        """Initialize truth-seeking algorithmic approaches."""

        self.truth_algorithms = {
            "multi_source_verification": {
                "min_sources": 3,
                "source_independence": True,
                "credibility_weighting": True,
                "bias_adjustment": True,
            },
            "consistency_analysis": {
                "internal_consistency": True,
                "temporal_consistency": True,
                "logical_consistency": True,
                "factual_consistency": True,
            },
            "contradiction_detection": {
                "direct_contradictions": True,
                "implicit_contradictions": True,
                "temporal_contradictions": True,
                "logical_contradictions": True,
            },
            "evidence_strength_assessment": {
                "documentary_evidence": 1.0,
                "eyewitness_testimony": 0.7,
                "circumstantial_evidence": 0.5,
                "hearsay": 0.3,
                "anonymous_sources": 0.4,
            },
            "bias_detection": {
                "confirmation_bias": True,
                "selection_bias": True,
                "reporting_bias": True,
                "political_bias": True,
            },
        }

    async def detect_hidden_patterns(
        self, data_sources: List[Any], detection_modes: Optional[List[str]] = None
    ) -> List[HiddenPattern]:
        """
        Detect hidden patterns across multiple data sources.

        Args:
            data_sources: List of data sources to analyze
            detection_modes: Specific detection modes to run

        Returns:
            List of detected hidden patterns
        """
        patterns = []

        try:
            # Default to all detection modes if none specified
            if detection_modes is None:
                detection_modes = list(self.detection_algorithms.keys())

            logger.info(
                f"Starting hidden pattern detection with modes: {detection_modes}"
            )

            # Preprocess and normalize data
            normalized_data = await self._preprocess_data(data_sources)

            # Run each detection algorithm
            for mode in detection_modes:
                try:
                    mode_patterns = await self._run_detection_algorithm(
                        mode, normalized_data
                    )
                    patterns.extend(mode_patterns)
                    logger.info(f"Detected {len(mode_patterns)} patterns using {mode}")

                except Exception as e:
                    logger.warning(f"Detection mode {mode} failed: {e}")
                    continue

            # Cross-correlate patterns to find meta-patterns
            meta_patterns = await self._detect_meta_patterns(patterns)
            patterns.extend(meta_patterns)

            # Score and rank patterns by significance
            ranked_patterns = self._rank_patterns_by_significance(patterns)

            # Apply truth-seeking analysis
            truth_analyzed_patterns = await self._apply_truth_analysis(ranked_patterns)

            logger.info(
                f"Detected {len(truth_analyzed_patterns)} total hidden patterns"
            )

            return truth_analyzed_patterns

        except Exception as e:
            logger.error(f"Hidden pattern detection failed: {e}")
            return []

    async def _preprocess_data(self, data_sources: List[Any]) -> Dict[str, Any]:
        """Preprocess and normalize data for pattern detection."""
        normalized = {
            "entities": set(),
            "relationships": [],
            "events": [],
            "documents": [],
            "temporal_data": [],
            "geographic_data": [],
            "financial_data": [],
            "network_data": defaultdict(list),
        }

        try:
            for source in data_sources:
                if isinstance(source, str):
                    # Text data - extract entities and relationships
                    extracted = await self._extract_from_text(source)
                    self._merge_extracted_data(normalized, extracted)

                elif isinstance(source, dict):
                    # Structured data
                    self._process_structured_data(normalized, source)

                elif isinstance(source, CrossReferenceHit):
                    # Cross-reference hit data
                    extracted = await self._extract_from_hit(source)
                    self._merge_extracted_data(normalized, extracted)

                elif isinstance(source, list):
                    # List of items - recurse
                    for item in source:
                        sub_normalized = await self._preprocess_data([item])
                        self._merge_normalized_data(normalized, sub_normalized)

            # Additional processing
            normalized["entity_count"] = len(normalized["entities"])
            normalized["relationship_graph"] = self._build_relationship_graph(
                normalized["relationships"]
            )

            return normalized

        except Exception as e:
            logger.error(f"Data preprocessing failed: {e}")
            return normalized

    def _process_structured_data(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Process structured data into normalized format."""
        try:
            # Extract entities
            if "entities" in source:
                entities = source["entities"]
                if isinstance(entities, list):
                    target["entities"].update(entities)
                elif isinstance(entities, set):
                    target["entities"].update(entities)

            # Extract relationships
            if "relationships" in source:
                relationships = source["relationships"]
                if isinstance(relationships, list):
                    target["relationships"].extend(relationships)

            # Extract other data types
            for key in ["events", "documents", "temporal_data", "geographic_data", "financial_data"]:
                if key in source and isinstance(source[key], list):
                    target[key].extend(source[key])

        except Exception as e:
            logger.warning(f"Structured data processing failed: {e}")

    def _merge_normalized_data(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Merge normalized data from multiple sources."""
        try:
            for key, value in source.items():
                if key == "entities" and isinstance(value, set):
                    target[key].update(value)
                elif key in target and isinstance(target[key], list) and isinstance(value, list):
                    target[key].extend(value)
                elif key == "network_data" and isinstance(value, dict):
                    for k, v in value.items():
                        if isinstance(v, list):
                            target[key][k].extend(v)
                else:
                    target[key] = value
        except Exception as e:
            logger.warning(f"Normalized data merging failed: {e}")

    async def _extract_from_text(self, text: str) -> Dict[str, Any]:
        """Extract structured data from text using various techniques."""
        extracted = {
            "entities": set(),
            "relationships": [],
            "events": [],
            "temporal_data": [],
            "geographic_data": [],
            "financial_data": [],
        }

        try:
            # Named entity recognition patterns
            entity_patterns = {
                "person": r"\b([A-Z][a-z]+\s+[A-Z][a-z]+)\b",
                "organization": r"\b([A-Z][a-z]+\s+(?:Inc|Corp|LLC|Ltd|Company|Corporation|Group|Holdings|Trust|Foundation))\b",
                "location": r"\b([A-Z][a-z]+(?:,\s*[A-Z]{2})?)\b",
                "date": r"\b(\d{1,2}/\d{1,2}/\d{2,4}|\d{4}-\d{2}-\d{2}|\w+\s+\d{1,2},?\s+\d{4})\b",
                "money": r"\$[\d,]+(?:\.\d{2})?(?:\s*(?:million|billion|thousand))?",
                "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "phone": r"\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b",
            }

            for entity_type, pattern in entity_patterns.items():
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    extracted["entities"].add(f"{entity_type}:{match}")

                    if entity_type == "date":
                        extracted["temporal_data"].append(match)
                    elif entity_type == "location":
                        extracted["geographic_data"].append(match)
                    elif entity_type == "money":
                        extracted["financial_data"].append(match)

            # Relationship extraction
            relationship_patterns = [
                r"(\w+)\s+(?:owns|controls|manages|directs)\s+(\w+)",
                r"(\w+)\s+(?:connected to|linked to|associated with)\s+(\w+)",
                r"(\w+)\s+(?:paid|transferred|sent)\s+.*?\s+to\s+(\w+)",
                r"(\w+)\s+and\s+(\w+)\s+(?:worked together|collaborated|partnered)",
            ]

            for pattern in relationship_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if len(match) == 2:
                        extracted["relationships"].append(
                            {
                                "source": match[0],
                                "target": match[1],
                                "type": "inferred",
                                "evidence": text[
                                    max(0, text.find(match[0]) - 50) : text.find(
                                        match[0]
                                    )
                                    + 100
                                ],
                            }
                        )

            # Use LLM for enhanced extraction if available
            if self.llm_engine.active_backend:
                try:
                    llm_extraction = await self.llm_engine.analyze_osint_data(
                        text, "entity_extraction"
                    )
                    # Merge LLM results
                    if hasattr(llm_extraction, "insights") and llm_extraction.insights:
                        extracted["llm_entities"] = llm_extraction.insights
                    else:
                        extracted["llm_entities"] = []
                except Exception as e:
                    logger.debug(f"LLM extraction failed: {e}")

            return extracted

        except Exception as e:
            logger.warning(f"Text extraction failed: {e}")
            return extracted

    async def _extract_from_hit(self, hit: CrossReferenceHit) -> Dict[str, Any]:
        """Extract data from cross-reference hit."""
        extracted = await self._extract_from_text(hit.content)

        # Add hit-specific data
        extracted["source"] = hit.source
        extracted["url"] = hit.url
        extracted["timestamp"] = hit.timestamp
        extracted["patterns_detected"] = hit.patterns_detected
        extracted["hidden_indicators"] = hit.hidden_indicators
        extracted["conspiracy_markers"] = hit.conspiracy_markers

        return extracted

    def _merge_extracted_data(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Merge extracted data into target structure."""
        try:
            for key, value in source.items():
                if key == "entities" and isinstance(value, set):
                    target[key].update(value)
                elif key in target and isinstance(target[key], list):
                    if isinstance(value, list):
                        target[key].extend(value)
                    else:
                        target[key].append(value)
                else:
                    target[key] = value
        except Exception as e:
            logger.warning(f"Data merging failed: {e}")

    def _build_relationship_graph(
        self, relationships: List[Dict[str, Any]]
    ) -> nx.Graph:
        """Build NetworkX graph from relationships."""
        graph = nx.Graph()

        try:
            for rel in relationships:
                source = rel.get("source", "")
                target = rel.get("target", "")
                rel_type = rel.get("type", "unknown")

                if source and target:
                    graph.add_edge(source, target, relationship_type=rel_type, **rel)

            return graph

        except Exception as e:
            logger.warning(f"Graph building failed: {e}")
            return graph

    async def _run_detection_algorithm(
        self, mode: str, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Run a specific detection algorithm."""
        patterns = []

        try:
            if mode == "temporal_correlation":
                patterns = await self._detect_temporal_correlations(data)
            elif mode == "geographic_clustering":
                patterns = await self._detect_geographic_clusters(data)
            elif mode == "entity_network_analysis":
                patterns = await self._analyze_entity_networks(data)
            elif mode == "linguistic_analysis":
                patterns = await self._analyze_linguistic_patterns(data)
            elif mode == "financial_flow_analysis":
                patterns = await self._analyze_financial_flows(data)
            elif mode == "behavioral_anomaly_detection":
                patterns = await self._detect_behavioral_anomalies(data)
            elif mode == "misdirection_analysis":
                patterns = await self._detect_misdirection(data)
            elif mode == "correlation_analysis":
                patterns = await self._analyze_correlations(data)

            return patterns

        except Exception as e:
            logger.warning(f"Algorithm {mode} failed: {e}")
            return []

    async def _detect_temporal_correlations(
        self, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Detect suspicious temporal correlations."""
        patterns = []

        try:
            temporal_data = data.get("temporal_data", [])

            if len(temporal_data) < 2:
                return patterns

            # Parse dates and create timeline
            parsed_dates = []
            for date_str in temporal_data:
                try:
                    # Try multiple date formats
                    for fmt in ["%m/%d/%Y", "%Y-%m-%d", "%B %d, %Y", "%b %d, %Y"]:
                        try:
                            parsed_date = datetime.strptime(date_str, fmt)
                            parsed_dates.append(parsed_date)
                            break
                        except ValueError:
                            continue
                except Exception:
                    continue

            if len(parsed_dates) < 2:
                return patterns

            # Analyze temporal patterns
            sorted_dates = sorted(parsed_dates)

            # Check for suspicious clustering
            for window in self.detection_algorithms["temporal_correlation"][
                "window_sizes"
            ]:
                clusters = self._find_temporal_clusters(sorted_dates, window)
                for cluster in clusters:
                    if len(cluster) >= 3:  # At least 3 events in cluster
                        pattern = HiddenPattern(
                            pattern_id=f"temporal_cluster_{len(patterns)}",
                            pattern_type="temporal_correlation",
                            pattern_name="Suspicious Temporal Clustering",
                            description=f"Multiple events clustered within {window}",
                            confidence_score=0.7 + (len(cluster) * 0.05),
                            significance_level=0.8,
                            temporal_markers=cluster,
                            evidence=[
                                f"Events: {[d.strftime('%Y-%m-%d') for d in cluster]}"
                            ],
                        )
                        patterns.append(pattern)

            # Check for sequential patterns
            intervals = []
            for i in range(len(sorted_dates) - 1):
                interval = sorted_dates[i + 1] - sorted_dates[i]
                intervals.append(interval)

            # Look for regular intervals (possible coordination)
            if len(intervals) >= 3:
                avg_interval = sum(intervals, timedelta()) / len(intervals)
                variance = statistics.variance([i.total_seconds() for i in intervals])

                if variance < (
                    avg_interval.total_seconds() * 0.1
                ):  # Low variance = regular pattern
                    pattern = HiddenPattern(
                        pattern_id=f"temporal_regular_{len(patterns)}",
                        pattern_type="temporal_correlation",
                        pattern_name="Regular Temporal Pattern",
                        description=f"Events occur with regular interval of ~{avg_interval}",
                        confidence_score=0.6,
                        significance_level=0.7,
                        temporal_markers=sorted_dates,
                        evidence=[
                            f"Average interval: {avg_interval}, Variance: {variance:.2f}"
                        ],
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Temporal correlation detection failed: {e}")
            return []

    def _find_temporal_clusters(
        self, dates: List[datetime], window: timedelta
    ) -> List[List[datetime]]:
        """Find clusters of dates within a time window."""
        clusters = []

        try:
            if not dates:
                return clusters

            current_cluster = [dates[0]]

            for i in range(1, len(dates)):
                if dates[i] - current_cluster[-1] <= window:
                    current_cluster.append(dates[i])
                else:
                    if len(current_cluster) >= 2:
                        clusters.append(current_cluster)
                    current_cluster = [dates[i]]

            # Add final cluster if it has multiple events
            if len(current_cluster) >= 2:
                clusters.append(current_cluster)

            return clusters

        except Exception as e:
            logger.warning(f"Temporal clustering failed: {e}")
            return []

    async def _detect_geographic_clusters(
        self, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Detect unusual geographic clustering patterns."""
        patterns = []

        try:
            geographic_data = data.get("geographic_data", [])

            if len(geographic_data) < 3:
                return patterns

            # Count location frequencies
            location_counts = Counter(geographic_data)

            # Find locations with unusual concentration
            for location, count in location_counts.items():
                if count >= 3:  # Threshold for suspicious clustering
                    total_locations = len(geographic_data)
                    concentration_ratio = count / total_locations

                    if (
                        concentration_ratio > 0.3
                    ):  # More than 30% of activity in one location
                        pattern = HiddenPattern(
                            pattern_id=f"geo_cluster_{len(patterns)}",
                            pattern_type="geographic_clustering",
                            pattern_name="Suspicious Geographic Concentration",
                            description=f"Unusual concentration of activity in {location}",
                            confidence_score=0.6 + (concentration_ratio * 0.3),
                            significance_level=0.7,
                            geographic_markers=[location],
                            evidence=[
                                f"Location: {location}, Count: {count}, Ratio: {concentration_ratio:.2f}"
                            ],
                        )
                        patterns.append(pattern)

            # Look for geographic patterns using clustering
            if len(set(geographic_data)) >= 3:
                # Simple clustering based on co-occurrence
                # In a real implementation, you would use actual coordinates and DBSCAN
                unique_locations = list(set(geographic_data))

                # Check for hub-and-spoke patterns
                for location in unique_locations:
                    connected_locations = [
                        loc for loc in unique_locations if loc != location
                    ]
                    if len(connected_locations) >= 3:
                        pattern = HiddenPattern(
                            pattern_id=f"geo_hub_{len(patterns)}",
                            pattern_type="geographic_clustering",
                            pattern_name="Geographic Hub Pattern",
                            description=f"{location} appears to be a geographic hub",
                            confidence_score=0.5,
                            significance_level=0.6,
                            geographic_markers=[location] + connected_locations[:3],
                            evidence=[
                                f"Hub: {location}, Connected: {len(connected_locations)}"
                            ],
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Geographic clustering detection failed: {e}")
            return []

    async def _analyze_entity_networks(
        self, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Analyze entity networks for hidden structures."""
        patterns = []

        try:
            graph = data.get("relationship_graph", nx.Graph())

            if graph.number_of_nodes() < 3:
                return patterns

            # Detect shell company networks
            shell_patterns = await self._detect_shell_networks(graph)
            patterns.extend(shell_patterns)

            # Detect proxy structures
            proxy_patterns = await self._detect_proxy_structures(graph)
            patterns.extend(proxy_patterns)

            # Detect hub entities (potential control nodes)
            hub_patterns = await self._detect_hub_entities(graph)
            patterns.extend(hub_patterns)

            # Detect isolated clusters (potential separate operations)
            cluster_patterns = await self._detect_isolated_clusters(graph)
            patterns.extend(cluster_patterns)

            return patterns

        except Exception as e:
            logger.warning(f"Entity network analysis failed: {e}")
            return []

    async def _detect_shell_networks(self, graph: nx.Graph) -> List[HiddenPattern]:
        """Detect potential shell company networks."""
        patterns = []

        try:
            # Look for entities with high connectivity but low activity indicators
            for node in graph.nodes():
                degree = len(list(graph.neighbors(node)))

                # High connectivity might indicate shell/proxy structure
                if degree >= 3:
                    # Check for shell company indicators in node attributes or name
                    node_str = str(node).lower()
                    shell_indicators = 0

                    shell_keywords = [
                        "inc",
                        "corp",
                        "llc",
                        "ltd",
                        "holdings",
                        "trust",
                        "services",
                    ]
                    for keyword in shell_keywords:
                        if keyword in node_str:
                            shell_indicators += 1

                    if shell_indicators >= 2 or degree >= 5:
                        neighbors = list(graph.neighbors(node))

                        pattern = HiddenPattern(
                            pattern_id=f"shell_network_{len(patterns)}",
                            pattern_type="entity_network_analysis",
                            pattern_name="Potential Shell Network",
                            description=f"Entity {node} shows shell company characteristics",
                            confidence_score=0.4
                            + (shell_indicators * 0.1)
                            + (degree * 0.05),
                            significance_level=0.6,
                            entities_involved=[node] + neighbors[:5],
                            evidence=[
                                f"High connectivity: {degree}",
                                f"Shell indicators: {shell_indicators}",
                            ],
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Shell network detection failed: {e}")
            return []

    async def _detect_proxy_structures(self, graph: nx.Graph) -> List[HiddenPattern]:
        """Detect proxy/cutout structures."""
        patterns = []

        try:
            # Look for entities that appear to be intermediaries
            for node in graph.nodes():
                neighbors = list(graph.neighbors(node))

                if len(neighbors) == 2:  # Potential intermediary
                    # Check if the two neighbors are not directly connected
                    neighbor1, neighbor2 = neighbors[0], neighbors[1]

                    if not graph.has_edge(neighbor1, neighbor2):
                        # This node might be a proxy/cutout
                        pattern = HiddenPattern(
                            pattern_id=f"proxy_structure_{len(patterns)}",
                            pattern_type="entity_network_analysis",
                            pattern_name="Potential Proxy Structure",
                            description=f"Entity {node} appears to be intermediary between {neighbor1} and {neighbor2}",
                            confidence_score=0.6,
                            significance_level=0.7,
                            entities_involved=[node, neighbor1, neighbor2],
                            evidence=[
                                f"Intermediary: {node}",
                                f"Endpoints: {neighbor1}, {neighbor2}",
                            ],
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Proxy structure detection failed: {e}")
            return []

    async def _detect_hub_entities(self, graph: nx.Graph) -> List[HiddenPattern]:
        """Detect hub entities that might be control nodes."""
        patterns = []

        try:
            # Calculate centrality measures
            if graph.number_of_nodes() < 3:
                return patterns

            betweenness_centrality = nx.betweenness_centrality(graph)
            degree_centrality = nx.degree_centrality(graph)

            # Find entities with high centrality scores
            for node, betweenness in betweenness_centrality.items():
                degree = degree_centrality[node]

                # High centrality indicates potential control node
                if betweenness > 0.3 or degree > 0.5:
                    neighbors = list(graph.neighbors(node))

                    pattern = HiddenPattern(
                        pattern_id=f"hub_entity_{len(patterns)}",
                        pattern_type="entity_network_analysis",
                        pattern_name="Potential Control Hub",
                        description=f"Entity {node} has high network centrality",
                        confidence_score=0.5 + (betweenness * 0.3) + (degree * 0.2),
                        significance_level=0.7,
                        entities_involved=[node] + neighbors[:5],
                        evidence=[
                            f"Betweenness centrality: {betweenness:.3f}",
                            f"Degree centrality: {degree:.3f}",
                        ],
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Hub entity detection failed: {e}")
            return []

    async def _detect_isolated_clusters(self, graph: nx.Graph) -> List[HiddenPattern]:
        """Detect isolated clusters that might represent separate operations."""
        patterns = []

        try:
            # Find connected components
            components = list(nx.connected_components(graph))

            if len(components) > 1:
                for i, component in enumerate(components):
                    if len(component) >= 3:  # Significant cluster
                        subgraph = graph.subgraph(component)
                        density = nx.density(subgraph)

                        pattern = HiddenPattern(
                            pattern_id=f"isolated_cluster_{i}",
                            pattern_type="entity_network_analysis",
                            pattern_name="Isolated Network Cluster",
                            description=f"Isolated cluster of {len(component)} entities",
                            confidence_score=0.5 + (density * 0.3),
                            significance_level=0.6,
                            entities_involved=list(component)[:10],
                            evidence=[
                                f"Cluster size: {len(component)}",
                                f"Density: {density:.3f}",
                            ],
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Isolated cluster detection failed: {e}")
            return []

    async def _analyze_linguistic_patterns(
        self, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Analyze linguistic patterns for deception and obfuscation."""
        patterns = []

        try:
            documents = data.get("documents", [])

            for doc_idx, doc in enumerate(documents):
                if isinstance(doc, str):
                    # Detect obfuscation patterns
                    obfuscation_score = self._calculate_obfuscation_score(doc)

                    if obfuscation_score > 0.5:
                        pattern = HiddenPattern(
                            pattern_id=f"linguistic_obfuscation_{doc_idx}",
                            pattern_type="linguistic_analysis",
                            pattern_name="Linguistic Obfuscation",
                            description="Document shows signs of deliberate obfuscation",
                            confidence_score=obfuscation_score,
                            significance_level=0.6,
                            evidence=[f"Obfuscation score: {obfuscation_score:.3f}"],
                            obfuscation_indicators=self._extract_obfuscation_indicators(
                                doc
                            ),
                        )
                        patterns.append(pattern)

                    # Detect euphemisms and code words
                    euphemism_patterns = self._detect_euphemisms(doc)
                    if euphemism_patterns:
                        pattern = HiddenPattern(
                            pattern_id=f"euphemism_detection_{doc_idx}",
                            pattern_type="linguistic_analysis",
                            pattern_name="Euphemism Usage",
                            description="Document contains euphemisms that may hide true meaning",
                            confidence_score=0.4 + (len(euphemism_patterns) * 0.1),
                            significance_level=0.5,
                            evidence=euphemism_patterns,
                            obfuscation_indicators=euphemism_patterns,
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Linguistic pattern analysis failed: {e}")
            return []

    def _calculate_obfuscation_score(self, text: str) -> float:
        """Calculate obfuscation score for text."""
        try:
            score = 0.0
            text_lower = text.lower()

            # Check for obfuscation patterns
            for pattern_type, patterns in self.obfuscation_patterns.items():
                matches = 0
                for pattern in patterns:
                    matches += len(re.findall(pattern, text_lower, re.IGNORECASE))

                # Normalize by text length
                if len(text) > 0:
                    normalized_matches = matches / (
                        len(text.split()) / 100
                    )  # Per 100 words
                    score += normalized_matches * 0.1

            # Additional linguistic complexity indicators
            sentences = text.split(".")
            if sentences:
                avg_sentence_length = sum(len(s.split()) for s in sentences) / len(
                    sentences
                )
                if avg_sentence_length > 30:  # Very long sentences
                    score += 0.1

            # Check for excessive jargon
            jargon_indicators = [
                "pursuant to",
                "heretofore",
                "aforementioned",
                "whereas",
                "notwithstanding",
            ]
            jargon_count = sum(
                1 for indicator in jargon_indicators if indicator in text_lower
            )
            score += jargon_count * 0.05

            return min(score, 1.0)

        except Exception as e:
            logger.warning(f"Obfuscation score calculation failed: {e}")
            return 0.0

    def _extract_obfuscation_indicators(self, text: str) -> List[str]:
        """Extract specific obfuscation indicators from text."""
        indicators = []

        try:
            text_lower = text.lower()

            for pattern_type, patterns in self.obfuscation_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, text_lower, re.IGNORECASE)
                    for match in matches:
                        indicators.append(f"{pattern_type}: {match}")

            return indicators

        except Exception as e:
            logger.warning(f"Obfuscation indicator extraction failed: {e}")
            return []

    def _detect_euphemisms(self, text: str) -> List[str]:
        """Detect euphemisms and code words."""
        euphemisms = []

        try:
            euphemism_patterns = {
                "consulting services": "lobbying/influence peddling",
                "strategic partnership": "quid pro quo arrangement",
                "business development": "relationship building for favors",
                "advisory role": "influence without accountability",
                "facilitation fee": "bribe",
                "expediting payment": "bribe",
                "consulting agreement": "influence purchase",
                "board position": "reward for services",
                "speaking engagement": "payment disguised as legitimate activity",
                "charitable contribution": "influence purchase",
            }

            text_lower = text.lower()

            for euphemism, meaning in euphemism_patterns.items():
                if euphemism in text_lower:
                    euphemisms.append(f"'{euphemism}' (likely meaning: {meaning})")

            return euphemisms

        except Exception as e:
            logger.warning(f"Euphemism detection failed: {e}")
            return []

    async def _analyze_financial_flows(
        self, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Analyze financial flows for laundering and structuring patterns."""
        patterns = []

        try:
            financial_data = data.get("financial_data", [])

            if not financial_data:
                return patterns

            # Extract monetary amounts
            amounts = []
            for item in financial_data:
                # Extract numeric values from financial data
                amount_matches = re.findall(r"\$?([\d,]+)(?:\.\d{2})?", str(item))
                for match in amount_matches:
                    try:
                        amount = float(match.replace(",", ""))
                        amounts.append(amount)
                    except ValueError:
                        continue

            if len(amounts) < 2:
                return patterns

            # Detect structuring patterns (amounts just under reporting thresholds)
            structuring_thresholds = [
                9999,
                49999,
                99999,
            ]  # Just under common reporting thresholds

            for threshold in structuring_thresholds:
                near_threshold = [
                    a for a in amounts if threshold - 1000 <= a <= threshold
                ]

                if len(near_threshold) >= 2:
                    pattern = HiddenPattern(
                        pattern_id=f"structuring_{threshold}",
                        pattern_type="financial_flow_analysis",
                        pattern_name="Potential Structuring",
                        description=f"Multiple transactions near ${threshold:,} threshold",
                        confidence_score=0.6 + (len(near_threshold) * 0.1),
                        significance_level=0.7,
                        evidence=[
                            f"Transactions near ${threshold:,}: {near_threshold}"
                        ],
                    )
                    patterns.append(pattern)

            # Detect round number patterns (possible coordination)
            round_amounts = [a for a in amounts if a % 1000 == 0 or a % 5000 == 0]

            if len(round_amounts) >= 3:
                pattern = HiddenPattern(
                    pattern_id="round_numbers",
                    pattern_type="financial_flow_analysis",
                    pattern_name="Round Number Pattern",
                    description="Multiple round-number transactions (possible coordination)",
                    confidence_score=0.4 + (len(round_amounts) * 0.05),
                    significance_level=0.5,
                    evidence=[f"Round amounts: {round_amounts}"],
                )
                patterns.append(pattern)

            # Detect layering patterns (complex transaction chains)
            if len(amounts) >= 5:
                # Simple statistical analysis for unusual patterns
                mean_amount = statistics.mean(amounts)
                median_amount = statistics.median(amounts)

                # Look for bimodal distribution (possible layering)
                if abs(mean_amount - median_amount) > mean_amount * 0.5:
                    pattern = HiddenPattern(
                        pattern_id="layering_pattern",
                        pattern_type="financial_flow_analysis",
                        pattern_name="Potential Layering",
                        description="Transaction pattern suggests possible layering",
                        confidence_score=0.5,
                        significance_level=0.6,
                        evidence=[
                            f"Mean: ${mean_amount:,.2f}, Median: ${median_amount:,.2f}"
                        ],
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Financial flow analysis failed: {e}")
            return []

    async def _detect_behavioral_anomalies(
        self, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Detect behavioral anomalies that might indicate deception."""
        patterns = []

        try:
            # This would analyze behavioral patterns in communications, timing, etc.
            # For now, implement basic patterns

            events = data.get("events", [])
            temporal_data = data.get("temporal_data", [])

            # Detect unusual timing patterns in behavior
            if len(temporal_data) >= 3:
                # Check for activity during unusual hours (possible avoidance behavior)
                unusual_time_indicators = [
                    "friday afternoon",
                    "late night",
                    "weekend",
                    "holiday",
                    "after hours",
                    "during distraction",
                    "while attention elsewhere",
                ]

                unusual_timing_count = 0
                for event in events:
                    event_str = str(event).lower()
                    for indicator in unusual_time_indicators:
                        if indicator in event_str:
                            unusual_timing_count += 1
                            break

                if unusual_timing_count >= 2:
                    pattern = HiddenPattern(
                        pattern_id="behavioral_timing",
                        pattern_type="behavioral_anomaly_detection",
                        pattern_name="Unusual Timing Behavior",
                        description="Pattern of activity during unusual times",
                        confidence_score=0.4 + (unusual_timing_count * 0.1),
                        significance_level=0.6,
                        evidence=[f"Unusual timing instances: {unusual_timing_count}"],
                        temporal_markers=temporal_data,
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Behavioral anomaly detection failed: {e}")
            return []

    async def _detect_misdirection(self, data: Dict[str, Any]) -> List[HiddenPattern]:
        """Detect deliberate misdirection and distraction tactics."""
        patterns = []

        try:
            documents = data.get("documents", [])

            for doc_idx, doc in enumerate(documents):
                if isinstance(doc, str):
                    misdirection_score = 0.0
                    misdirection_indicators = []

                    # Check for misdirection patterns
                    for (
                        pattern_type,
                        patterns_list,
                    ) in self.obfuscation_patterns.items():
                        if pattern_type == "misdirection_tactics":
                            for pattern in patterns_list:
                                matches = re.findall(pattern, doc, re.IGNORECASE)
                                if matches:
                                    misdirection_score += 0.2
                                    misdirection_indicators.extend(matches)

                    # Check for information overload tactics
                    word_count = len(doc.split())
                    if word_count > 1000:  # Very long document
                        # Check ratio of relevant to irrelevant information
                        # This is a simplified check - could be more sophisticated
                        if (
                            "however" in doc.lower()
                            or "on the other hand" in doc.lower()
                        ):
                            misdirection_score += 0.1

                    # Check for red herring patterns
                    red_herring_indicators = [
                        "more importantly",
                        "the real issue is",
                        "what about",
                        "instead of focusing on",
                        "the bigger picture",
                        "you should be asking",
                        "the real question",
                    ]

                    for indicator in red_herring_indicators:
                        if indicator in doc.lower():
                            misdirection_score += 0.15
                            misdirection_indicators.append(indicator)

                    if misdirection_score > 0.3:
                        pattern = HiddenPattern(
                            pattern_id=f"misdirection_{doc_idx}",
                            pattern_type="misdirection_analysis",
                            pattern_name="Deliberate Misdirection",
                            description="Document shows signs of deliberate misdirection",
                            confidence_score=misdirection_score,
                            significance_level=0.6,
                            evidence=misdirection_indicators,
                            obfuscation_indicators=misdirection_indicators,
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Misdirection detection failed: {e}")
            return []

    async def _analyze_correlations(
        self, data: Dict[str, Any]
    ) -> List[HiddenPattern]:
        """Analyze correlations between different data dimensions."""
        patterns = []

        try:
            # Extract different data dimensions
            entities = data.get("entities", set())
            temporal_data = data.get("temporal_data", [])
            geographic_data = data.get("geographic_data", [])
            financial_data = data.get("financial_data", [])

            # Analyze entity-temporal correlations
            entity_temporal_patterns = await self._analyze_entity_temporal_correlations(
                entities, temporal_data
            )
            patterns.extend(entity_temporal_patterns)

            # Analyze geographic-financial correlations
            geo_financial_patterns = await self._analyze_geographic_financial_correlations(
                geographic_data, financial_data
            )
            patterns.extend(geo_financial_patterns)

            # Analyze entity-geographic correlations
            entity_geo_patterns = await self._analyze_entity_geographic_correlations(
                entities, geographic_data
            )
            patterns.extend(entity_geo_patterns)

            # Analyze multi-dimensional correlations
            multi_dim_patterns = await self._analyze_multi_dimensional_correlations(
                entities, temporal_data, geographic_data, financial_data
            )
            patterns.extend(multi_dim_patterns)

            return patterns

        except Exception as e:
            logger.warning(f"Correlation analysis failed: {e}")
            return []

    async def _analyze_entity_temporal_correlations(
        self, entities: set, temporal_data: List[str]
    ) -> List[HiddenPattern]:
        """Analyze correlations between entities and temporal patterns."""
        patterns = []

        try:
            if not entities or not temporal_data:
                return patterns

            # Group temporal data by entities (simplified approach)
            entity_temporal_associations = defaultdict(list)

            # This is a simplified correlation - in practice, you'd need more structured data
            for entity in entities:
                for temporal_item in temporal_data:
                    # Check if entity appears near temporal data in original sources
                    # For now, create synthetic correlations based on co-occurrence patterns
                    if len(temporal_data) > 1:
                        # Look for patterns where entities appear with multiple temporal markers
                        entity_temporal_associations[entity].append(temporal_item)

            # Detect entities with multiple temporal associations
            for entity, temporal_items in entity_temporal_associations.items():
                if len(temporal_items) >= 3:  # Entity appears with multiple time markers
                    pattern = HiddenPattern(
                        pattern_id=f"entity_temporal_corr_{len(patterns)}",
                        pattern_type="correlation_analysis",
                        pattern_name="Entity-Temporal Correlation",
                        description=f"Entity {entity} shows correlation with multiple temporal markers",
                        confidence_score=0.5 + (len(temporal_items) * 0.1),
                        significance_level=0.7,
                        entities_involved=[str(entity)],
                        temporal_markers=temporal_items,
                        evidence=[
                            f"Entity associated with {len(temporal_items)} temporal markers",
                            f"Temporal markers: {temporal_items[:3]}",
                        ],
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Entity-temporal correlation analysis failed: {e}")
            return []

    async def _analyze_geographic_financial_correlations(
        self, geographic_data: List[str], financial_data: List[str]
    ) -> List[HiddenPattern]:
        """Analyze correlations between geographic and financial patterns."""
        patterns = []

        try:
            if not geographic_data or not financial_data:
                return patterns

            # Group financial data by geographic locations
            geo_financial_associations = defaultdict(list)

            # Simplified correlation analysis
            for geo_item in geographic_data:
                for financial_item in financial_data:
                    # In practice, you'd need structured data linking locations to amounts
                    # For now, detect patterns where high-value transactions correlate with locations
                    financial_str = str(financial_item).lower()
                    if any(amount in financial_str for amount in ["million", "billion", "$"]):
                        geo_financial_associations[geo_item].append(financial_item)

            # Detect suspicious geographic-financial correlations
            for location, financial_items in geo_financial_associations.items():
                if len(financial_items) >= 2:
                    # Calculate total financial volume (simplified)
                    high_value_count = sum(
                        1 for item in financial_items
                        if any(term in str(item).lower() for term in ["million", "billion"])
                    )

                    if high_value_count >= 2:
                        pattern = HiddenPattern(
                            pattern_id=f"geo_financial_corr_{len(patterns)}",
                            pattern_type="correlation_analysis",
                            pattern_name="Geographic-Financial Correlation",
                            description=f"Location {location} shows correlation with high-value financial activity",
                            confidence_score=0.6 + (high_value_count * 0.1),
                            significance_level=0.8,
                            geographic_markers=[location],
                            evidence=[
                                f"High-value transactions: {high_value_count}",
                                f"Location: {location}",
                                f"Associated financial items: {len(financial_items)}",
                            ],
                        )
                        patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Geographic-financial correlation analysis failed: {e}")
            return []

    async def _analyze_entity_geographic_correlations(
        self, entities: set, geographic_data: List[str]
    ) -> List[HiddenPattern]:
        """Analyze correlations between entities and geographic locations."""
        patterns = []

        try:
            if not entities or not geographic_data:
                return patterns

            # Group geographic data by entities
            entity_geo_associations = defaultdict(set)

            # Simplified entity-geographic correlation
            for entity in entities:
                for geo_item in geographic_data:
                    # In practice, you'd have structured relationships
                    # For now, detect entities associated with multiple locations
                    if len(geographic_data) > 1:
                        entity_geo_associations[entity].add(geo_item)

            # Detect entities with multi-location presence
            for entity, locations in entity_geo_associations.items():
                if len(locations) >= 3:  # Entity associated with multiple locations
                    pattern = HiddenPattern(
                        pattern_id=f"entity_geo_corr_{len(patterns)}",
                        pattern_type="correlation_analysis",
                        pattern_name="Entity-Geographic Correlation",
                        description=f"Entity {entity} shows presence across multiple geographic locations",
                        confidence_score=0.5 + (len(locations) * 0.1),
                        significance_level=0.7,
                        entities_involved=[str(entity)],
                        geographic_markers=list(locations),
                        evidence=[
                            f"Locations: {list(locations)}",
                            f"Geographic spread: {len(locations)} locations",
                        ],
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Entity-geographic correlation analysis failed: {e}")
            return []

    async def _analyze_multi_dimensional_correlations(
        self, entities: set, temporal_data: List[str], geographic_data: List[str], financial_data: List[str]
    ) -> List[HiddenPattern]:
        """Analyze correlations across multiple dimensions simultaneously."""
        patterns = []

        try:
            # Look for entities that correlate across multiple dimensions
            multi_dim_entities = defaultdict(dict)

            for entity in entities:
                entity_str = str(entity)
                multi_dim_entities[entity_str] = {
                    "temporal_count": len([t for t in temporal_data if entity_str.lower() in str(t).lower()]),
                    "geographic_count": len([g for g in geographic_data if entity_str.lower() in str(g).lower()]),
                    "financial_count": len([f for f in financial_data if entity_str.lower() in str(f).lower()]),
                }

            # Detect entities with correlations across multiple dimensions
            for entity, counts in multi_dim_entities.items():
                dimension_count = sum(1 for count in counts.values() if count > 0)

                if dimension_count >= 3:  # Entity appears in 3+ dimensions
                    total_correlations = sum(counts.values())

                    pattern = HiddenPattern(
                        pattern_id=f"multi_dim_corr_{len(patterns)}",
                        pattern_type="correlation_analysis",
                        pattern_name="Multi-Dimensional Correlation",
                        description=f"Entity {entity} shows correlations across multiple data dimensions",
                        confidence_score=0.6 + (dimension_count * 0.1) + (total_correlations * 0.05),
                        significance_level=0.8,
                        entities_involved=[entity],
                        evidence=[
                            f"Dimensions correlated: {dimension_count}",
                            f"Temporal: {counts['temporal_count']}, Geographic: {counts['geographic_count']}, Financial: {counts['financial_count']}",
                        ],
                    )
                    patterns.append(pattern)

            return patterns

        except Exception as e:
            logger.warning(f"Multi-dimensional correlation analysis failed: {e}")
            return []

    async def _detect_meta_patterns(
        self, patterns: List[HiddenPattern]
    ) -> List[HiddenPattern]:
        """Detect meta-patterns across multiple detected patterns."""
        meta_patterns = []

        try:
            if len(patterns) < 3:
                return meta_patterns

            # Group patterns by type
            pattern_groups = defaultdict(list)
            for pattern in patterns:
                pattern_groups[pattern.pattern_type].append(pattern)

            # Detect coordination across pattern types
            if len(pattern_groups) >= 3:
                meta_pattern = HiddenPattern(
                    pattern_id="meta_coordination",
                    pattern_type="meta_pattern",
                    pattern_name="Multi-Domain Coordination",
                    description="Coordination detected across multiple domains",
                    confidence_score=0.7,
                    significance_level=0.8,
                    evidence=[f"Pattern types involved: {list(pattern_groups.keys())}"],
                    entities_involved=list(
                        set(sum([p.entities_involved for p in patterns], []))
                    ),
                )
                meta_patterns.append(meta_pattern)

            # Detect temporal meta-patterns
            temporal_patterns = [p for p in patterns if p.temporal_markers]
            if len(temporal_patterns) >= 2:
                all_times = []
                for tp in temporal_patterns:
                    all_times.extend(tp.temporal_markers)

                if len(all_times) >= 5:
                    # Check for coordinated timing across different pattern types
                    meta_pattern = HiddenPattern(
                        pattern_id="meta_temporal",
                        pattern_type="meta_pattern",
                        pattern_name="Cross-Domain Temporal Coordination",
                        description="Temporal coordination across multiple pattern types",
                        confidence_score=0.6,
                        significance_level=0.7,
                        temporal_markers=sorted(all_times),
                        evidence=[
                            f"Coordinated timing across {len(temporal_patterns)} pattern types"
                        ],
                    )
                    meta_patterns.append(meta_pattern)

            return meta_patterns

        except Exception as e:
            logger.warning(f"Meta-pattern detection failed: {e}")
            return []

    def _rank_patterns_by_significance(
        self, patterns: List[HiddenPattern]
    ) -> List[HiddenPattern]:
        """Rank patterns by significance and confidence."""
        try:
            # Calculate composite score
            for pattern in patterns:
                # Composite score based on confidence, significance, and evidence quantity
                evidence_score = min(len(pattern.evidence) * 0.1, 0.5)
                entity_score = min(len(pattern.entities_involved) * 0.05, 0.3)

                composite_score = (
                    pattern.confidence_score * 0.4
                    + pattern.significance_level * 0.4
                    + evidence_score
                    + entity_score
                )

                pattern.truth_probability = min(composite_score, 1.0)

            # Sort by composite score
            patterns.sort(key=lambda p: p.truth_probability, reverse=True)

            return patterns

        except Exception as e:
            logger.warning(f"Pattern ranking failed: {e}")
            return patterns

    async def _apply_truth_analysis(
        self, patterns: List[HiddenPattern]
    ) -> List[HiddenPattern]:
        """Apply truth-seeking analysis to patterns."""
        try:
            for pattern in patterns:
                # Apply truth algorithms
                truth_score = await self._calculate_truth_score(pattern)
                pattern.truth_probability = truth_score

                # Add analyst notes based on truth analysis
                if truth_score > 0.8:
                    pattern.analyst_notes = (
                        "High probability - recommend immediate investigation"
                    )
                elif truth_score > 0.6:
                    pattern.analyst_notes = "Moderate probability - worth investigating"
                elif truth_score > 0.4:
                    pattern.analyst_notes = (
                        "Low probability - monitor for additional evidence"
                    )
                else:
                    pattern.analyst_notes = (
                        "Very low probability - likely false positive"
                    )

            return patterns

        except Exception as e:
            logger.warning(f"Truth analysis failed: {e}")
            return patterns

    async def _calculate_truth_score(self, pattern: HiddenPattern) -> float:
        """Calculate truth probability score for a pattern."""
        try:
            base_score = pattern.confidence_score

            # Adjust based on evidence quality
            evidence_quality = 0.5  # Default

            if pattern.evidence:
                # Check for high-quality evidence indicators
                evidence_text = " ".join(str(e) for e in pattern.evidence).lower()

                # High-quality indicators
                quality_indicators = (
                    self.truth_indicators["documentary_evidence"]
                    + self.truth_indicators["verification_markers"]
                )

                quality_matches = sum(
                    1
                    for indicator in quality_indicators
                    if re.search(indicator, evidence_text, re.IGNORECASE) is not None
                )

                evidence_quality = min(0.3 + (quality_matches * 0.1), 1.0)

            # Adjust based on obfuscation level
            obfuscation_penalty = len(pattern.obfuscation_indicators) * 0.05

            # Adjust based on pattern type reliability
            type_reliability = {
                "temporal_correlation": 0.8,
                "geographic_clustering": 0.7,
                "entity_network_analysis": 0.9,
                "linguistic_analysis": 0.6,
                "financial_flow_analysis": 0.85,
                "behavioral_anomaly_detection": 0.5,
                "misdirection_analysis": 0.7,
                "meta_pattern": 0.9,
            }

            reliability_factor = type_reliability.get(pattern.pattern_type, 0.5)

            # Calculate final truth score
            truth_score = (
                base_score * 0.4
                + evidence_quality * 0.3
                + reliability_factor * 0.2
                + pattern.significance_level * 0.1
                - obfuscation_penalty
            )

            return max(0.0, min(truth_score, 1.0))

        except Exception as e:
            logger.warning(f"Truth score calculation failed: {e}")
            return pattern.confidence_score

    async def generate_investigation_report(
        self, patterns: List[HiddenPattern]
    ) -> Dict[str, Any]:
        """Generate comprehensive investigation report."""
        try:
            # High-confidence patterns
            high_confidence = [p for p in patterns if p.truth_probability > 0.7]
            medium_confidence = [
                p for p in patterns if 0.4 < p.truth_probability <= 0.7
            ]
            low_confidence = [p for p in patterns if p.truth_probability <= 0.4]

            report: Dict[str, Any] = {
                "summary": {
                    "total_patterns": len(patterns),
                    "high_confidence": len(high_confidence),
                    "medium_confidence": len(medium_confidence),
                    "low_confidence": len(low_confidence),
                    "analysis_timestamp": datetime.now().isoformat(),
                },
                "key_findings": [],
                "investigation_priorities": [],
                "entity_network": {},
                "temporal_analysis": {},
                "recommendations": [],
            }

            # Key findings from high-confidence patterns
            for pattern in high_confidence[:10]:  # Top 10
                finding = {
                    "pattern_name": pattern.pattern_name,
                    "description": pattern.description,
                    "confidence": pattern.truth_probability,
                    "entities": pattern.entities_involved,
                    "evidence": pattern.evidence[:3],  # Top 3 pieces of evidence
                    "significance": pattern.significance_level,
                }
                report["key_findings"].append(finding)

            # Investigation priorities
            pattern_types = defaultdict(list)
            for pattern in high_confidence:
                pattern_types[pattern.pattern_type].append(pattern)

            for pattern_type, type_patterns in pattern_types.items():
                if len(type_patterns) >= 2:  # Multiple patterns of same type
                    priority = {
                        "area": pattern_type,
                        "pattern_count": len(type_patterns),
                        "avg_confidence": statistics.mean(
                            [p.truth_probability for p in type_patterns]
                        ),
                        "priority_level": (
                            "High" if len(type_patterns) >= 3 else "Medium"
                        ),
                    }
                    report["investigation_priorities"].append(priority)

            # Entity network analysis
            all_entities = []
            for pattern in patterns:
                all_entities.extend(pattern.entities_involved)

            entity_counts = Counter(all_entities)
            report["entity_network"] = {
                "key_entities": dict(entity_counts.most_common(10)),
                "total_entities": len(set(all_entities)),
                "interconnected_entities": len(
                    [e for e, c in entity_counts.items() if c >= 2]
                ),
            }

            # Temporal analysis
            all_temporal = []
            for pattern in patterns:
                all_temporal.extend(pattern.temporal_markers)

            if all_temporal:
                sorted_times = sorted(all_temporal)
                report["temporal_analysis"] = {
                    "time_span": {
                        "earliest": (
                            sorted_times[0].isoformat() if sorted_times else None
                        ),
                        "latest": (
                            sorted_times[-1].isoformat() if sorted_times else None
                        ),
                    },
                    "activity_clusters": len(
                        [
                            p
                            for p in patterns
                            if p.pattern_type == "temporal_correlation"
                        ]
                    ),
                    "suspicious_timing_events": len(
                        [p for p in patterns if "timing" in p.pattern_name.lower()]
                    ),
                }

            # Recommendations
            report["recommendations"] = [
                "Focus investigation on high-confidence patterns with multiple supporting evidence",
                "Investigate entities appearing in multiple patterns",
                "Analyze temporal clusters for coordinated activities",
                "Cross-reference findings with additional data sources",
                "Consider obfuscation indicators as signs of deliberate concealment",
                "Prioritize patterns showing financial flow anomalies",
                "Examine meta-patterns for broader conspiracy indicators",
            ]

            # Add pattern-specific recommendations
            for pattern in high_confidence[:5]:
                if pattern.pattern_type == "entity_network_analysis":
                    report["recommendations"].append(
                        f"Investigate network structure around {pattern.entities_involved[0] if pattern.entities_involved else 'key entity'}"
                    )
                elif pattern.pattern_type == "financial_flow_analysis":
                    report["recommendations"].append(
                        "Conduct detailed financial investigation and transaction analysis"
                    )
                elif pattern.pattern_type == "temporal_correlation":
                    report["recommendations"].append(
                        "Analyze timing patterns for evidence of coordination"
                    )

            return report

        except Exception as e:
            logger.error(f"Investigation report generation failed: {e}")
            return {"error": str(e)}


# Factory function
def create_hidden_pattern_detector() -> HiddenPatternDetector:
    """Create and initialize hidden pattern detector."""
    return HiddenPatternDetector()


# Example usage
if __name__ == "__main__":

    async def demo():
        """Demonstrate hidden pattern detection capabilities."""
        detector = create_hidden_pattern_detector()

        print("Hidden Pattern Detection Framework Demo")
        print("=====================================")

        # Example data
        sample_data = [
            "Mossack Fonseca created shell companies for multiple clients in Panama",
            "Transactions of $9,950 occurred three times in one week",
            "John Smith serves as nominee director for fifteen companies",
            "Meetings occurred just before major policy announcements",
            "Consulting services agreement signed for strategic partnership",
        ]

        # Detect patterns
        patterns = await detector.detect_hidden_patterns(sample_data)

        print(f"\nDetected {len(patterns)} hidden patterns:")
        for pattern in patterns[:5]:  # Show top 5
            print(f"\n• {pattern.pattern_name}")
            print(f"  Type: {pattern.pattern_type}")
            print(f"  Confidence: {pattern.confidence_score:.2f}")
            print(f"  Truth Probability: {pattern.truth_probability:.2f}")
            print(f"  Description: {pattern.description}")
            if pattern.evidence:
                print(
                    f"  Evidence: {pattern.evidence[0] if pattern.evidence else 'None'}"
                )

        # Generate investigation report
        report = await detector.generate_investigation_report(patterns)
        print("\nInvestigation Report Summary:")
        print(f"Total patterns: {report['summary']['total_patterns']}")
        print(f"High confidence: {report['summary']['high_confidence']}")
        print(f"Key findings: {len(report['key_findings'])}")

    asyncio.run(demo())
