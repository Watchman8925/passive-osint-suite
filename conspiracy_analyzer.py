#!/usr/bin/env python3
"""
Conspiracy Theory Analyzer Module
Advanced analysis for detecting conspiracy patterns in intelligence data.
"""

import logging
import re
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from collections import Counter

logger = logging.getLogger(__name__)

class ConspiracyTheoryAnalyzer:
    """Advanced conspiracy theory analyzer"""

    def __init__(self):
        self.enabled = True

        # Conspiracy pattern indicators
        self.conspiracy_keywords = {
            'high': ['conspiracy', 'cover-up', 'false flag', 'deep state', 'shadow government',
                    'illuminati', 'new world order', 'cabal', 'elite', 'puppet masters'],
            'medium': ['controlled', 'manipulated', 'hoax', 'psyop', 'disinformation',
                      'mainstream media', 'fake news', 'crisis actor', 'staged'],
            'low': ['theory', 'speculation', 'alternative', 'narrative', 'hidden truth']
        }

        # Source credibility indicators
        self.credibility_indicators = {
            'high_credibility': ['.gov', '.edu', '.org', 'reuters', 'ap', 'bbc', 'nytimes'],
            'low_credibility': ['conspiracy', 'truth', 'alternative', 'freedom', 'patriot']
        }

        # Temporal pattern analysis
        self.suspicious_timing_patterns = [
            'coordinated', 'simultaneous', 'convenient', 'perfect timing'
        ]

        logger.info("ConspiracyTheoryAnalyzer initialized with pattern detection")

    def analyze_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data for conspiracy patterns"""
        try:
            text_content = self._extract_text_content(data)
            if not text_content:
                return {"conspiracy_score": 0.0, "patterns": [], "confidence": 0.0}

            # Calculate conspiracy score
            conspiracy_score = self._calculate_conspiracy_score(text_content)

            # Detect specific patterns
            patterns = self._detect_conspiracy_patterns(text_content)

            # Analyze source credibility
            source_analysis = self._analyze_source_credibility(data)

            # Check for manipulation indicators
            manipulation_indicators = self._detect_manipulation_indicators(data)

            confidence = min(1.0, (conspiracy_score + len(patterns) * 0.1) / 2.0)

            return {
                "conspiracy_score": conspiracy_score,
                "patterns": patterns,
                "confidence": confidence,
                "source_analysis": source_analysis,
                "manipulation_indicators": manipulation_indicators,
                "risk_level": self._calculate_risk_level(conspiracy_score, patterns)
            }

        except Exception as e:
            logger.error(f"Failed to analyze conspiracy patterns: {e}")
            return {"conspiracy_score": 0.0, "patterns": [], "confidence": 0.0, "error": str(e)}

    def _extract_text_content(self, data: Dict[str, Any]) -> str:
        """Extract text content from various data formats"""
        text_parts = []

        # Extract from common fields
        for field in ['content', 'text', 'description', 'title', 'summary']:
            if field in data and data[field]:
                text_parts.append(str(data[field]))

        # Extract from metadata
        if 'metadata' in data and isinstance(data['metadata'], dict):
            for key, value in data['metadata'].items():
                if isinstance(value, str):
                    text_parts.append(value)

        return ' '.join(text_parts).lower()

    def _calculate_conspiracy_score(self, text: str) -> float:
        """Calculate conspiracy theory score based on keyword analysis"""
        score = 0.0
        total_words = len(text.split())

        if total_words == 0:
            return 0.0

        # High weight keywords
        for keyword in self.conspiracy_keywords['high']:
            count = text.count(keyword)
            score += count * 5.0

        # Medium weight keywords
        for keyword in self.conspiracy_keywords['medium']:
            count = text.count(keyword)
            score += count * 2.0

        # Low weight keywords
        for keyword in self.conspiracy_keywords['low']:
            count = text.count(keyword)
            score += count * 0.5

        # Normalize by text length (prevent gaming by repetition)
        normalized_score = score / (total_words + 1)

        return min(1.0, normalized_score)

    def _detect_conspiracy_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Detect specific conspiracy theory patterns"""
        patterns = []

        # Pattern 1: Overuse of conspiracy keywords
        keyword_density = sum(text.count(kw) for kw in self.conspiracy_keywords['high'])
        if keyword_density > 3:
            patterns.append({
                "type": "keyword_density",
                "description": f"High density of conspiracy keywords ({keyword_density} occurrences)",
                "severity": "high"
            })

        # Pattern 2: Appeal to hidden knowledge
        hidden_knowledge_indicators = ['secret', 'hidden', 'they don\'t want you to know', 'forbidden knowledge']
        for indicator in hidden_knowledge_indicators:
            if indicator in text:
                patterns.append({
                    "type": "hidden_knowledge",
                    "description": f"Appeal to hidden knowledge: '{indicator}'",
                    "severity": "medium"
                })

        # Pattern 3: Us vs Them mentality
        us_them_indicators = ['they', 'them', 'elite', 'globalists', 'cabal']
        us_them_count = sum(text.count(indicator) for indicator in us_them_indicators)
        if us_them_count > 5:
            patterns.append({
                "type": "us_vs_them",
                "description": f"Strong us-vs-them mentality ({us_them_count} references)",
                "severity": "medium"
            })

        # Pattern 4: Questioning official narratives
        official_narrative_indicators = ['official story', 'mainstream media', 'fake news', 'controlled narrative']
        for indicator in official_narrative_indicators:
            if indicator in text:
                patterns.append({
                    "type": "narrative_questioning",
                    "description": f"Questioning official narratives: '{indicator}'",
                    "severity": "low"
                })

        return patterns

    def _analyze_source_credibility(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the credibility of information sources"""
        credibility_score = 0.5  # Default neutral

        # Check source URL/domain
        source_url = data.get('source', data.get('url', ''))
        if source_url:
            domain = self._extract_domain(source_url)

            # High credibility domains
            if any(cred_domain in domain for cred_domain in self.credibility_indicators['high_credibility']):
                credibility_score = 0.8
            # Low credibility domains
            elif any(low_cred in domain for low_cred in self.credibility_indicators['low_credibility']):
                credibility_score = 0.2

        return {
            "credibility_score": credibility_score,
            "source_domain": self._extract_domain(source_url) if source_url else "unknown",
            "assessment": "high" if credibility_score > 0.7 else "low" if credibility_score < 0.3 else "medium"
        }

    def _detect_manipulation_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect potential manipulation indicators"""
        indicators = []

        # Check for temporal anomalies
        timestamps = []
        for key in ['created_at', 'published_at', 'timestamp']:
            if key in data and data[key]:
                try:
                    if isinstance(data[key], str):
                        timestamps.append(datetime.fromisoformat(data[key].replace('Z', '+00:00')))
                    elif isinstance(data[key], datetime):
                        timestamps.append(data[key])
                except:
                    pass

        if len(timestamps) > 1:
            time_span = max(timestamps) - min(timestamps)
            if time_span < timedelta(minutes=5) and len(timestamps) > 3:
                indicators.append({
                    "type": "temporal_anomaly",
                    "description": f"Suspiciously rapid sequence of events ({time_span})",
                    "severity": "medium"
                })

        # Check for content anomalies
        content = self._extract_text_content(data)
        if content:
            # Check for excessive repetition
            words = content.split()
            word_counts = Counter(words)
            repeated_words = [word for word, count in word_counts.items() if count > 10]
            if repeated_words:
                indicators.append({
                    "type": "content_repetition",
                    "description": f"Excessive repetition of words: {repeated_words[:3]}",
                    "severity": "low"
                })

        return indicators

    def _calculate_risk_level(self, score: float, patterns: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level"""
        high_severity = sum(1 for p in patterns if p.get('severity') == 'high')
        medium_severity = sum(1 for p in patterns if p.get('severity') == 'medium')

        risk_score = score + (high_severity * 0.3) + (medium_severity * 0.1)

        if risk_score > 0.8:
            return "critical"
        elif risk_score > 0.6:
            return "high"
        elif risk_score > 0.4:
            return "medium"
        elif risk_score > 0.2:
            return "low"
        else:
            return "minimal"

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return url.lower()

    def detect_manipulation(self, sources: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect potential manipulation across multiple sources"""
        try:
            if not sources:
                return {"manipulation_detected": False, "confidence": 0.0}

            # Analyze each source for conspiracy patterns
            source_analyses = []
            for source in sources:
                analysis = self.analyze_patterns(source)
                source_analyses.append(analysis)

            # Cross-source analysis
            avg_conspiracy_score = sum(a['conspiracy_score'] for a in source_analyses) / len(source_analyses)

            # Check for coordinated messaging
            common_patterns = []
            all_patterns = [p for analysis in source_analyses for p in analysis.get('patterns', [])]
            pattern_counts = Counter(str(p) for p in all_patterns)

            for pattern_str, count in pattern_counts.items():
                if count > len(sources) * 0.7:  # Pattern appears in >70% of sources
                    common_patterns.append(pattern_str)

            # Check for temporal coordination
            timestamps = []
            for source in sources:
                for key in ['created_at', 'published_at', 'timestamp']:
                    if key in source and source[key]:
                        try:
                            if isinstance(source[key], str):
                                timestamps.append(datetime.fromisoformat(source[key].replace('Z', '+00:00')))
                        except:
                            pass

            temporal_coordination = False
            time_span = None
            if len(timestamps) > 1:
                time_span = max(timestamps) - min(timestamps)
                if time_span < timedelta(hours=1) and len(timestamps) > 2:
                    temporal_coordination = True

            manipulation_detected = (
                avg_conspiracy_score > 0.6 or
                len(common_patterns) > 2 or
                temporal_coordination
            )

            confidence = min(1.0, (avg_conspiracy_score + len(common_patterns) * 0.1 + (0.3 if temporal_coordination else 0)))

            return {
                "manipulation_detected": manipulation_detected,
                "confidence": confidence,
                "avg_conspiracy_score": avg_conspiracy_score,
                "common_patterns_count": len(common_patterns),
                "temporal_coordination": temporal_coordination,
                "evidence": {
                    "common_patterns": common_patterns[:5],  # Limit to first 5
                    "source_count": len(sources),
                    "time_span_minutes": time_span.total_seconds() / 60 if time_span is not None else None
                }
            }

        except Exception as e:
            logger.error(f"Failed to detect manipulation: {e}")
            return {"manipulation_detected": False, "confidence": 0.0, "error": str(e)}