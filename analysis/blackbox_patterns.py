"""
Blackbox OSINT Pattern Analysis Engine
=====================================

Advanced pattern recognition and search intelligence system that operates
without external API dependencies. This module provides sophisticated
pattern analysis capabilities for OSINT investigations using local
intelligence and machine learning techniques.

Features:
- Pattern recognition in multiple data types
- Advanced Google dorking and search optimization
- Behavioral pattern analysis
- Network relationship mapping
- Temporal pattern detection
- Anomaly identification
- Local knowledge base integration
"""

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# Import local dependencies
from local_llm_engine import create_local_llm_engine

logger = logging.getLogger(__name__)

@dataclass
class PatternSignature:
    """Represents a detected pattern signature."""
    pattern_id: str
    pattern_type: str
    confidence: float
    indicators: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.now)
    occurrences: int = 1

@dataclass
class SearchStrategy:
    """Advanced search strategy for OSINT investigation."""
    strategy_id: str
    target_type: str
    search_terms: List[str]
    dorks: List[str]
    platforms: List[str]
    priority: int
    expected_results: List[str] = field(default_factory=list)

@dataclass
class IntelligenceFragment:
    """Single piece of intelligence with context."""
    fragment_id: str
    source: str
    content: str
    fragment_type: str
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)
    related_fragments: List[str] = field(default_factory=list)

class BlackboxPatternEngine:
    """
    Advanced pattern analysis engine for OSINT investigations.
    
    This engine analyzes data patterns, generates search strategies,
    and identifies intelligence opportunities without relying on
    external APIs or services.
    """
    
    def __init__(self):
        self.patterns = {}
        self.knowledge_base = defaultdict(list)
        self.search_strategies = {}
        self.intelligence_fragments = {}
        self.llm_engine = create_local_llm_engine()
        
        # Initialize pattern libraries
        self._load_pattern_libraries()
        self._load_search_strategies()
        
    def _load_pattern_libraries(self):
        """Load comprehensive pattern libraries for various data types."""
        
        # Email patterns
        self.patterns['email'] = {
            'corporate_email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'disposable_email': r'[a-zA-Z0-9._%+-]+@(tempmail|guerrillamail|10minutemail|mailinator)',
            'government_email': r'[a-zA-Z0-9._%+-]+@.*\.(gov|mil|edu)',
            'executive_email': r'(ceo|cto|cfo|president|director|vp|exec).*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        }
        
        # Domain patterns
        self.patterns['domain'] = {
            'subdomain_enumeration': r'([a-zA-Z0-9-]+\.)+[a-zA-Z0-9.-]+',
            'suspicious_tld': r'.*\.(tk|ml|ga|cf|gq|bit|onion)',
            'typosquatting': r'[a-zA-Z0-9-]*([il1o0]|rn|vv|nn)[a-zA-Z0-9-]*',
            'dga_domain': r'[a-z]{8,20}\.(com|net|org|info)'
        }
        
        # IP patterns
        self.patterns['ip'] = {
            'private_ip': r'(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)',
            'tor_exit': r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
            'cloud_provider': r'(aws|azure|gcp|digitalocean|linode)',
            'suspicious_geolocation': r'(russia|china|north korea|iran)'
        }
        
        # Cryptocurrency patterns
        self.patterns['crypto'] = {
            'bitcoin_address': r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}',
            'ethereum_address': r'0x[a-fA-F0-9]{40}',
            'monero_address': r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}',
            'exchange_pattern': r'(binance|coinbase|kraken|bitfinex|huobi)'
        }
        
        # Social media patterns
        self.patterns['social'] = {
            'username_pattern': r'@[a-zA-Z0-9_]{3,20}',
            'linkedin_profile': r'linkedin\.com/in/[a-zA-Z0-9-]+',
            'twitter_profile': r'twitter\.com/[a-zA-Z0-9_]+',
            'github_profile': r'github\.com/[a-zA-Z0-9-]+',
            'telegram_channel': r't\.me/[a-zA-Z0-9_]+'
        }
        
        # Phone number patterns
        self.patterns['phone'] = {
            'us_phone': r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            'international': r'\+[1-9]\d{1,14}',
            'voip_pattern': r'(skype|discord|telegram|whatsapp)',
            'burner_indicators': r'(prepaid|temporary|disposable)'
        }
        
    def _load_search_strategies(self):
        """Load advanced search strategies for different investigation types."""
        
        self.search_strategies = {
            'person_investigation': SearchStrategy(
                strategy_id='person_001',
                target_type='person',
                search_terms=['{name}', '"{full_name}"', '{email}', '{phone}'],
                dorks=[
                    'site:linkedin.com "{name}"',
                    'site:facebook.com "{name}"',
                    'site:twitter.com "{name}"',
                    '"{email}" -site:linkedin.com',
                    'filetype:pdf "{name}"',
                    'intitle:"{name}" curriculum OR resume OR CV'
                ],
                platforms=['google', 'bing', 'duckduckgo', 'yandex'],
                priority=1
            ),
            
            'company_investigation': SearchStrategy(
                strategy_id='company_001',
                target_type='company',
                search_terms=['{company}', '"{company_name}"', '{domain}'],
                dorks=[
                    'site:{domain}',
                    'site:{domain} filetype:pdf',
                    'site:sec.gov "{company}"',
                    'employees site:linkedin.com "{company}"',
                    'inurl:about OR inurl:team site:{domain}',
                    '"{company}" press release',
                    '"{company}" financial statement'
                ],
                platforms=['google', 'bing', 'sec.gov', 'edgar'],
                priority=1
            ),
            
            'domain_investigation': SearchStrategy(
                strategy_id='domain_001',
                target_type='domain',
                search_terms=['{domain}', '*.{domain}', '{registrant}'],
                dorks=[
                    'site:{domain}',
                    'site:*.{domain}',
                    'inurl:{domain}',
                    'link:{domain}',
                    '"{domain}" -site:{domain}',
                    'whois "{domain}"',
                    'ssl certificate "{domain}"'
                ],
                platforms=['google', 'bing', 'shodan', 'censys'],
                priority=2
            ),
            
            'breach_investigation': SearchStrategy(
                strategy_id='breach_001',
                target_type='breach',
                search_terms=['{email}', '{domain}', '{company}'],
                dorks=[
                    '"{email}" breach OR leak OR dump',
                    '"{domain}" database OR sql OR breach',
                    'site:pastebin.com "{email}"',
                    'site:ghostbin.com "{email}"',
                    'filetype:sql "{domain}"',
                    '"{company}" credential OR password leak'
                ],
                platforms=['google', 'bing', 'dehashed', 'haveibeenpwned'],
                priority=3
            )
        }
    
    def analyze_patterns(self, data: str, data_type: str = 'mixed') -> List[PatternSignature]:
        """
        Analyze data for patterns and anomalies.
        
        Args:
            data: Input data to analyze
            data_type: Type of data (email, domain, ip, crypto, social, mixed)
            
        Returns:
            List of detected pattern signatures
        """
        detected_patterns = []
        
        try:
            if data_type == 'mixed' or data_type in self.patterns:
                pattern_groups = [data_type] if data_type != 'mixed' else self.patterns.keys()
                
                for group in pattern_groups:
                    for pattern_name, pattern_regex in self.patterns[group].items():
                        matches = re.findall(pattern_regex, data, re.IGNORECASE)
                        
                        if matches:
                            confidence = self._calculate_pattern_confidence(
                                pattern_name, matches, data
                            )
                            
                            signature = PatternSignature(
                                pattern_id=f"{group}_{pattern_name}_{hashlib.md5(str(matches).encode()).hexdigest()[:8]}",
                                pattern_type=f"{group}.{pattern_name}",
                                confidence=confidence,
                                indicators=matches,
                                metadata={
                                    'data_type': group,
                                    'pattern_name': pattern_name,
                                    'match_count': len(matches),
                                    'data_snippet': data[:200] + '...' if len(data) > 200 else data
                                }
                            )
                            
                            detected_patterns.append(signature)
            
            # Enhanced analysis with local LLM if available
            if hasattr(self, 'llm_engine') and self.llm_engine.active_backend:
                llm_patterns = self._llm_enhanced_analysis(data, detected_patterns)
                detected_patterns.extend(llm_patterns)
            
            return detected_patterns
            
        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            return []
    
    def _calculate_pattern_confidence(self, pattern_name: str, matches: List[str], context: str) -> float:
        """Calculate confidence score for detected pattern."""
        base_confidence = 0.7
        
        # Adjust based on match count
        match_factor = min(len(matches) / 10.0, 0.2)
        
        # Adjust based on pattern type
        if 'suspicious' in pattern_name or 'tor' in pattern_name:
            base_confidence += 0.1
        
        # Adjust based on context
        if len(context) > 1000:  # More context usually means higher confidence
            context_factor = 0.1
        else:
            context_factor = 0.05
        
        return min(base_confidence + match_factor + context_factor, 1.0)
    
    async def _llm_enhanced_analysis(self, data: str, existing_patterns: List[PatternSignature]) -> List[PatternSignature]:
        """Use local LLM for enhanced pattern analysis."""
        try:
            analysis = await self.llm_engine.analyze_osint_data(data, 'pattern_analysis')
            
            enhanced_patterns = []
            
            for insight in analysis.insights:
                pattern_id = f"llm_insight_{hashlib.md5(insight.encode()).hexdigest()[:8]}"
                
                signature = PatternSignature(
                    pattern_id=pattern_id,
                    pattern_type="llm.insight",
                    confidence=0.8,
                    indicators=[insight],
                    metadata={
                        'source': 'local_llm',
                        'analysis_type': 'insight',
                        'existing_pattern_count': len(existing_patterns)
                    }
                )
                
                enhanced_patterns.append(signature)
            
            return enhanced_patterns
            
        except Exception as e:
            logger.warning(f"LLM enhanced analysis failed: {e}")
            return []
    
    def generate_search_strategies(self, target: str, target_type: str, 
                                 investigation_context: Optional[Dict] = None) -> List[str]:
        """
        Generate advanced search strategies for OSINT investigation.
        
        Args:
            target: Target to investigate
            target_type: Type of target (person, company, domain, etc.)
            investigation_context: Additional context for search optimization
            
        Returns:
            List of optimized search queries and dorks
        """
        search_queries = []
        
        try:
            # Get base strategy for target type
            if target_type in self.search_strategies:
                strategy = self.search_strategies[target_type]
                
                # Generate basic search terms
                for term_template in strategy.search_terms:
                    search_term = self._format_search_term(term_template, target, investigation_context)
                    if search_term:
                        search_queries.append(search_term)
                
                # Generate advanced dorks
                for dork_template in strategy.dorks:
                    dork = self._format_search_term(dork_template, target, investigation_context)
                    if dork:
                        search_queries.append(dork)
            
            # Generate contextual searches
            contextual_queries = self._generate_contextual_searches(target, target_type, investigation_context)
            search_queries.extend(contextual_queries)
            
            # Generate time-based searches
            temporal_queries = self._generate_temporal_searches(target, target_type)
            search_queries.extend(temporal_queries)
            
            # Remove duplicates and sort by effectiveness
            unique_queries = list(set(search_queries))
            
            return self._rank_search_queries(unique_queries, target_type)
            
        except Exception as e:
            logger.error(f"Search strategy generation failed: {e}")
            return [target]  # Fallback to basic search
    
    def _format_search_term(self, template: str, target: str, context: Optional[Dict] = None) -> Optional[str]:
        """Format search term template with target and context data."""
        try:
            # Basic substitutions
            formatted = template.replace('{target}', target)
            formatted = formatted.replace('{name}', target)
            formatted = formatted.replace('{domain}', target)
            formatted = formatted.replace('{company}', target)
            formatted = formatted.replace('{email}', target)
            
            # Context-based substitutions
            if context:
                for key, value in context.items():
                    formatted = formatted.replace(f'{{{key}}}', str(value))
            
            # Clean up any remaining placeholders
            if '{' in formatted and '}' in formatted:
                return None  # Don't return incomplete templates
            
            return formatted
            
        except Exception as e:
            logger.warning(f"Search term formatting failed: {e}")
            return None
    
    def _generate_contextual_searches(self, target: str, target_type: str, 
                                    context: Optional[Dict] = None) -> List[str]:
        """Generate contextual search queries based on investigation context."""
        contextual_queries = []
        
        try:
            if target_type == 'person':
                # Professional context
                contextual_queries.extend([
                    f'"{target}" LinkedIn profile',
                    f'"{target}" resume OR CV',
                    f'"{target}" professional background',
                    f'"{target}" work history',
                    f'"{target}" contact information'
                ])
                
                # Social context
                contextual_queries.extend([
                    f'"{target}" social media',
                    f'"{target}" Facebook profile',
                    f'"{target}" Twitter account',
                    f'"{target}" Instagram profile'
                ])
            
            elif target_type == 'company':
                # Business context
                contextual_queries.extend([
                    f'"{target}" employees',
                    f'"{target}" leadership team',
                    f'"{target}" financial information',
                    f'"{target}" partnerships',
                    f'"{target}" news OR press release'
                ])
                
                # Technical context
                contextual_queries.extend([
                    f'"{target}" technology stack',
                    f'"{target}" infrastructure',
                    f'"{target}" security breach',
                    f'"{target}" data leak'
                ])
            
            elif target_type == 'domain':
                # Technical context
                contextual_queries.extend([
                    f'whois "{target}"',
                    f'DNS records "{target}"',
                    f'SSL certificate "{target}"',
                    f'subdomain "{target}"',
                    f'"{target}" hosting provider'
                ])
                
                # Security context
                contextual_queries.extend([
                    f'"{target}" malware',
                    f'"{target}" phishing',
                    f'"{target}" blacklist',
                    f'"{target}" reputation'
                ])
            
            return contextual_queries
            
        except Exception as e:
            logger.warning(f"Contextual search generation failed: {e}")
            return []
    
    def _generate_temporal_searches(self, target: str, target_type: str) -> List[str]:
        """Generate time-based search queries for historical analysis."""
        temporal_queries = []
        
        try:
            # Time-based modifiers
            time_modifiers = [
                'after:2020',
                'after:2022',
                'before:2020',
                'daterange:2020-2024'
            ]
            
            base_queries = [
                f'"{target}"',
                f'{target} news',
                f'{target} announcement'
            ]
            
            for base_query in base_queries:
                for modifier in time_modifiers:
                    temporal_queries.append(f'{base_query} {modifier}')
            
            return temporal_queries
            
        except Exception as e:
            logger.warning(f"Temporal search generation failed: {e}")
            return []
    
    def _rank_search_queries(self, queries: List[str], target_type: str) -> List[str]:
        """Rank search queries by expected effectiveness."""
        try:
            # Priority scoring based on query characteristics
            scored_queries = []
            
            for query in queries:
                score = 0
                
                # Boost for specific search operators
                if 'site:' in query:
                    score += 10
                if 'filetype:' in query:
                    score += 8
                if 'intitle:' in query:
                    score += 6
                if 'inurl:' in query:
                    score += 5
                if '"' in query:  # Exact phrase
                    score += 7
                
                # Boost for target-specific queries
                if target_type in query.lower():
                    score += 5
                
                # Penalize overly broad queries
                if len(query.split()) == 1:
                    score -= 3
                
                scored_queries.append((score, query))
            
            # Sort by score (descending) and return queries
            scored_queries.sort(key=lambda x: x[0], reverse=True)
            
            return [query for _, query in scored_queries]
            
        except Exception as e:
            logger.warning(f"Query ranking failed: {e}")
            return queries
    
    def correlate_intelligence(self, fragments: List[IntelligenceFragment]) -> Dict[str, Any]:
        """
        Correlate intelligence fragments to identify relationships and patterns.
        
        Args:
            fragments: List of intelligence fragments to correlate
            
        Returns:
            Dictionary containing correlation analysis results
        """
        correlations = {
            'relationships': [],
            'clusters': [],
            'anomalies': [],
            'timeline': [],
            'confidence_scores': {}
        }
        
        try:
            # Identify direct relationships
            correlations['relationships'] = self._find_direct_relationships(fragments)
            
            # Cluster related fragments
            correlations['clusters'] = self._cluster_fragments(fragments)
            
            # Detect anomalies
            correlations['anomalies'] = self._detect_anomalies(fragments)
            
            # Build timeline
            correlations['timeline'] = self._build_timeline(fragments)
            
            # Calculate confidence scores
            correlations['confidence_scores'] = self._calculate_correlation_confidence(fragments)
            
            return correlations
            
        except Exception as e:
            logger.error(f"Intelligence correlation failed: {e}")
            return correlations
    
    def _find_direct_relationships(self, fragments: List[IntelligenceFragment]) -> List[Dict[str, Any]]:
        """Find direct relationships between intelligence fragments."""
        relationships = []
        
        try:
            for i, fragment1 in enumerate(fragments):
                for j, fragment2 in enumerate(fragments[i+1:], i+1):
                    similarity = self._calculate_fragment_similarity(fragment1, fragment2)
                    
                    if similarity > 0.7:  # High similarity threshold
                        relationships.append({
                            'fragment1_id': fragment1.fragment_id,
                            'fragment2_id': fragment2.fragment_id,
                            'similarity': similarity,
                            'relationship_type': self._determine_relationship_type(fragment1, fragment2),
                            'evidence': self._extract_relationship_evidence(fragment1, fragment2)
                        })
            
            return relationships
            
        except Exception as e:
            logger.warning(f"Relationship finding failed: {e}")
            return []
    
    def _calculate_fragment_similarity(self, fragment1: IntelligenceFragment, 
                                     fragment2: IntelligenceFragment) -> float:
        """Calculate similarity between two intelligence fragments."""
        try:
            # Simple text similarity (can be enhanced with more sophisticated algorithms)
            content1 = fragment1.content.lower()
            content2 = fragment2.content.lower()
            
            # Check for common keywords
            words1 = set(content1.split())
            words2 = set(content2.split())
            
            intersection = words1.intersection(words2)
            union = words1.union(words2)
            
            if len(union) == 0:
                return 0.0
            
            jaccard_similarity = len(intersection) / len(union)
            
            # Boost similarity for same source or type
            if fragment1.source == fragment2.source:
                jaccard_similarity += 0.1
            
            if fragment1.fragment_type == fragment2.fragment_type:
                jaccard_similarity += 0.1
            
            return min(jaccard_similarity, 1.0)
            
        except Exception as e:
            logger.warning(f"Similarity calculation failed: {e}")
            return 0.0
    
    def _determine_relationship_type(self, fragment1: IntelligenceFragment, 
                                   fragment2: IntelligenceFragment) -> str:
        """Determine the type of relationship between fragments."""
        try:
            if fragment1.source == fragment2.source:
                return "same_source"
            elif fragment1.fragment_type == fragment2.fragment_type:
                return "same_type"
            elif abs((fragment1.timestamp - fragment2.timestamp).total_seconds()) < 3600:
                return "temporal"
            else:
                return "content_similarity"
                
        except Exception as e:
            logger.warning(f"Relationship type determination failed: {e}")
            return "unknown"
    
    def _extract_relationship_evidence(self, fragment1: IntelligenceFragment, 
                                     fragment2: IntelligenceFragment) -> List[str]:
        """Extract evidence supporting the relationship between fragments."""
        evidence = []
        
        try:
            content1 = fragment1.content.lower()
            content2 = fragment2.content.lower()
            
            # Find common entities (emails, domains, names, etc.)
            for pattern_group in self.patterns.values():
                for pattern_name, pattern_regex in pattern_group.items():
                    matches1 = set(re.findall(pattern_regex, content1, re.IGNORECASE))
                    matches2 = set(re.findall(pattern_regex, content2, re.IGNORECASE))
                    
                    common_matches = matches1.intersection(matches2)
                    if common_matches:
                        evidence.extend([f"Common {pattern_name}: {match}" for match in common_matches])
            
            return evidence
            
        except Exception as e:
            logger.warning(f"Evidence extraction failed: {e}")
            return []
    
    def _cluster_fragments(self, fragments: List[IntelligenceFragment]) -> List[Dict[str, Any]]:
        """Cluster related intelligence fragments."""
        # Simplified clustering - can be enhanced with more sophisticated algorithms
        clusters = []
        processed = set()
        
        try:
            for fragment in fragments:
                if fragment.fragment_id in processed:
                    continue
                
                cluster = {
                    'cluster_id': f"cluster_{len(clusters)}",
                    'fragments': [fragment.fragment_id],
                    'cluster_type': fragment.fragment_type,
                    'confidence': fragment.confidence
                }
                
                # Find related fragments
                for other_fragment in fragments:
                    if (other_fragment.fragment_id != fragment.fragment_id and 
                        other_fragment.fragment_id not in processed):
                        
                        similarity = self._calculate_fragment_similarity(fragment, other_fragment)
                        if similarity > 0.5:  # Clustering threshold
                            cluster['fragments'].append(other_fragment.fragment_id)
                            processed.add(other_fragment.fragment_id)
                
                processed.add(fragment.fragment_id)
                clusters.append(cluster)
            
            return clusters
            
        except Exception as e:
            logger.warning(f"Fragment clustering failed: {e}")
            return []
    
    def _detect_anomalies(self, fragments: List[IntelligenceFragment]) -> List[Dict[str, Any]]:
        """Detect anomalies in intelligence fragments."""
        anomalies = []
        
        try:
            # Confidence-based anomalies
            confidences = [f.confidence for f in fragments]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            for fragment in fragments:
                if fragment.confidence < avg_confidence - 0.3:  # Significantly below average
                    anomalies.append({
                        'anomaly_type': 'low_confidence',
                        'fragment_id': fragment.fragment_id,
                        'details': f"Confidence {fragment.confidence} below average {avg_confidence:.2f}",
                        'severity': 'medium'
                    })
            
            # Temporal anomalies
            timestamps = [f.timestamp for f in fragments]
            if len(timestamps) > 1:
                time_gaps = []
                sorted_timestamps = sorted(timestamps)
                
                for i in range(1, len(sorted_timestamps)):
                    gap = (sorted_timestamps[i] - sorted_timestamps[i-1]).total_seconds()
                    time_gaps.append(gap)
                
                avg_gap = sum(time_gaps) / len(time_gaps) if time_gaps else 0
                
                for i, gap in enumerate(time_gaps):
                    if gap > avg_gap * 3:  # Unusually large time gap
                        anomalies.append({
                            'anomaly_type': 'temporal_gap',
                            'fragment_id': f"gap_{i}",
                            'details': f"Large time gap of {gap/3600:.1f} hours",
                            'severity': 'low'
                        })
            
            return anomalies
            
        except Exception as e:
            logger.warning(f"Anomaly detection failed: {e}")
            return []
    
    def _build_timeline(self, fragments: List[IntelligenceFragment]) -> List[Dict[str, Any]]:
        """Build chronological timeline of intelligence fragments."""
        try:
            # Sort fragments by timestamp
            sorted_fragments = sorted(fragments, key=lambda x: x.timestamp)
            
            timeline = []
            for fragment in sorted_fragments:
                timeline.append({
                    'timestamp': fragment.timestamp.isoformat(),
                    'fragment_id': fragment.fragment_id,
                    'source': fragment.source,
                    'type': fragment.fragment_type,
                    'summary': fragment.content[:100] + '...' if len(fragment.content) > 100 else fragment.content,
                    'confidence': fragment.confidence
                })
            
            return timeline
            
        except Exception as e:
            logger.warning(f"Timeline building failed: {e}")
            return []
    
    def _calculate_correlation_confidence(self, fragments: List[IntelligenceFragment]) -> Dict[str, float]:
        """Calculate confidence scores for correlation analysis."""
        try:
            total_fragments = len(fragments)
            avg_confidence = sum(f.confidence for f in fragments) / total_fragments if total_fragments > 0 else 0
            
            # Calculate various confidence metrics
            confidence_scores = {
                'overall_confidence': avg_confidence,
                'data_completeness': min(total_fragments / 10.0, 1.0),  # Normalize to 10 fragments
                'source_diversity': len(set(f.source for f in fragments)) / max(total_fragments, 1),
                'temporal_consistency': self._calculate_temporal_consistency(fragments),
                'correlation_strength': self._calculate_correlation_strength(fragments)
            }
            
            return confidence_scores
            
        except Exception as e:
            logger.warning(f"Correlation confidence calculation failed: {e}")
            return {'overall_confidence': 0.0}
    
    def _calculate_temporal_consistency(self, fragments: List[IntelligenceFragment]) -> float:
        """Calculate temporal consistency of intelligence fragments."""
        try:
            if len(fragments) < 2:
                return 1.0
            
            timestamps = [f.timestamp for f in fragments]
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            
            # Higher consistency for fragments clustered in time
            if time_span < 3600:  # Within 1 hour
                return 0.9
            elif time_span < 86400:  # Within 1 day
                return 0.7
            elif time_span < 604800:  # Within 1 week
                return 0.5
            else:
                return 0.3
                
        except Exception as e:
            logger.warning(f"Temporal consistency calculation failed: {e}")
            return 0.5
    
    def _calculate_correlation_strength(self, fragments: List[IntelligenceFragment]) -> float:
        """Calculate overall correlation strength between fragments."""
        try:
            if len(fragments) < 2:
                return 0.0
            
            total_pairs = len(fragments) * (len(fragments) - 1) / 2
            correlation_sum = 0
            
            for i, fragment1 in enumerate(fragments):
                for fragment2 in fragments[i+1:]:
                    similarity = self._calculate_fragment_similarity(fragment1, fragment2)
                    correlation_sum += similarity
            
            return correlation_sum / total_pairs if total_pairs > 0 else 0.0
            
        except Exception as e:
            logger.warning(f"Correlation strength calculation failed: {e}")
            return 0.0

# Factory function
def create_blackbox_pattern_engine() -> BlackboxPatternEngine:
    """Create and initialize a blackbox pattern engine."""
    return BlackboxPatternEngine()

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def demo():
        """Demonstrate blackbox pattern engine capabilities."""
        engine = create_blackbox_pattern_engine()
        
        print("Blackbox OSINT Pattern Engine Demo")
        print("=================================")
        
        # Example pattern analysis
        sample_data = """
        Contact: john.doe@example.com
        Website: https://suspicious-domain.tk
        Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Phone: +1-555-123-4567
        LinkedIn: linkedin.com/in/johndoe
        """
        
        patterns = engine.analyze_patterns(sample_data, 'mixed')
        print(f"\nDetected {len(patterns)} patterns:")
        for pattern in patterns:
            print(f"- {pattern.pattern_type}: {pattern.indicators} (confidence: {pattern.confidence:.2f})")
        
        # Example search strategy generation
        strategies = engine.generate_search_strategies("john.doe@example.com", "person")
        print(f"\nGenerated {len(strategies)} search strategies:")
        for i, strategy in enumerate(strategies[:5]):  # Show top 5
            print(f"{i+1}. {strategy}")
    
    asyncio.run(demo())