#!/usr/bin/env python3
"""
Blackbox Pattern Engine Module
Machine learning-based pattern recognition for intelligence analysis.
"""

import logging
import re
from typing import Any, Dict, List, Optional
from collections import Counter, defaultdict
import math
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    logger.warning("numpy not available - advanced ML features disabled")

class BlackboxPatternEngine:
    """Advanced pattern recognition engine using statistical and ML techniques"""

    def __init__(self):
        self.enabled = True

        # Pattern templates for different threat types
        self.threat_patterns = {
            'phishing': [
                r'(?i)(urgent|immediate|action.required|account.suspended)',
                r'(?i)(verify.your|confirm.your|update.your).*(account|password|information)',
                r'(?i)(click.here|login.now|verify.now)',
                r'(?i)(bank|paypal|amazon|microsoft|apple).*(security|alert|notification)'
            ],
            'malware': [
                r'(?i)(trojan|virus|malware|ransomware|spyware)',
                r'(?i)(exploit|vulnerability|zero.day)',
                r'(?i)(command.and.control|c2|c&c)',
                r'(?i)(payload|shellcode|backdoor)'
            ],
            'fraud': [
                r'(?i)(scam|fraud|deception|fake|counterfeit)',
                r'(?i)(419|advance.fee| nigerian.prince)',
                r'(?i)(lottery|inheritance|prize|winner)',
                r'(?i)(investment.opportunity|guaranteed.return)'
            ],
            'espionage': [
                r'(?i)(classified|secret|confidential|top.secret)',
                r'(?i)(intelligence|surveillance|monitoring)',
                r'(?i)(foreign.agent|spy|infiltration)',
                r'(?i)(data.exfiltration|information.theft)'
            ]
        }

        # Anomaly detection thresholds
        self.anomaly_thresholds = {
            'frequency_spike': 3.0,  # 3x normal frequency
            'unusual_timing': 0.8,   # 80% confidence for timing anomalies
            'rare_pattern': 0.1      # 10% occurrence rate for rare patterns
        }

        logger.info("BlackboxPatternEngine initialized with pattern recognition")

    def analyze_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data for patterns using statistical and rule-based methods"""
        try:
            patterns = []
            anomalies = []

            # Extract text content for analysis
            text_content = self._extract_text_for_analysis(data)
            if not text_content:
                return {"patterns": [], "anomalies": [], "confidence": 0.0}

            # Apply threat pattern matching
            threat_matches = self._match_threat_patterns(text_content)
            patterns.extend(threat_matches)

            # Statistical analysis
            statistical_patterns = self._statistical_pattern_analysis(data)
            patterns.extend(statistical_patterns)

            # Anomaly detection
            detected_anomalies = self._detect_anomalies(data)
            anomalies.extend(detected_anomalies)

            # Calculate overall confidence
            confidence = self._calculate_overall_confidence(patterns, anomalies)

            return {
                "patterns": patterns,
                "anomalies": anomalies,
                "confidence": confidence,
                "pattern_count": len(patterns),
                "anomaly_count": len(anomalies),
                "analysis_timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to analyze patterns: {e}")
            return {"patterns": [], "anomalies": [], "confidence": 0.0, "error": str(e)}

    def _extract_text_for_analysis(self, data: Dict[str, Any]) -> str:
        """Extract text content from various data formats"""
        text_parts = []

        # Extract from common fields
        for field in ['content', 'text', 'description', 'title', 'message', 'body']:
            if field in data and data[field]:
                text_parts.append(str(data[field]))

        # Extract from metadata
        if 'metadata' in data and isinstance(data['metadata'], dict):
            for key, value in data['metadata'].items():
                if isinstance(value, str):
                    text_parts.append(value)

        return ' '.join(text_parts).lower()

    def _match_threat_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Match text against known threat patterns"""
        matches = []

        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                regex_matches = re.findall(pattern, text)
                if regex_matches:
                    confidence = min(1.0, len(regex_matches) * 0.2)  # Scale confidence by match count

                    match = {
                        "type": threat_type,
                        "pattern": pattern,
                        "matches": regex_matches[:5],  # Limit to first 5 matches
                        "confidence": confidence,
                        "severity": "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low"
                    }
                    matches.append(match)

        return matches

    def _statistical_pattern_analysis(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform statistical pattern analysis"""
        patterns = []

        # Analyze text statistics
        text = self._extract_text_for_analysis(data)
        if len(text) > 50:  # Only analyze substantial text
            words = re.findall(r'\b\w+\b', text.lower())
            word_counts = Counter(words)

            # Detect repetitive patterns
            total_words = len(words)
            if total_words > 0:
                avg_word_freq = sum(word_counts.values()) / len(word_counts)
                repetitive_words = [word for word, count in word_counts.items()
                                  if count > avg_word_freq * 3]

                if repetitive_words:
                    patterns.append({
                        "type": "repetitive_content",
                        "description": f"Excessive repetition of words: {repetitive_words[:3]}",
                        "confidence": 0.6,
                        "severity": "medium",
                        "repetitive_words": repetitive_words
                    })

            # Detect unusual character patterns
            char_counts = Counter(text)
            total_chars = len(text)

            # High punctuation ratio might indicate obfuscation
            punctuation_chars = '.,!?;:()[]{}'
            punctuation_count = sum(char_counts.get(char, 0) for char in punctuation_chars)
            punctuation_ratio = punctuation_count / total_chars if total_chars > 0 else 0

            if punctuation_ratio > 0.15:  # More than 15% punctuation
                patterns.append({
                    "type": "unusual_punctuation",
                    "description": f"High punctuation ratio ({punctuation_ratio:.2%}) - possible obfuscation",
                    "confidence": 0.7,
                    "severity": "medium",
                    "punctuation_ratio": punctuation_ratio
                })

        return patterns

    def _detect_anomalies(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalous patterns in the data"""
        anomalies = []

        # Check for unusual timestamps
        if 'timestamp' in data or 'created_at' in data:
            timestamp_str = data.get('timestamp') or data.get('created_at')
            if timestamp_str:
                try:
                    # Check if timestamp is in the future or too old
                    if isinstance(timestamp_str, str):
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    elif isinstance(timestamp_str, datetime):
                        timestamp = timestamp_str
                    else:
                        timestamp = None

                    if timestamp:
                        now = datetime.now(timestamp.tzinfo) if timestamp.tzinfo else datetime.now()
                        time_diff = abs((timestamp - now).total_seconds())

                        # Future timestamp
                        if timestamp > now + timedelta(hours=1):
                            anomalies.append({
                                "type": "future_timestamp",
                                "description": f"Timestamp is in the future: {timestamp}",
                                "confidence": 0.9,
                                "severity": "high"
                            })

                        # Very old timestamp (more than 10 years)
                        elif time_diff > (365 * 24 * 60 * 60 * 10):
                            anomalies.append({
                                "type": "ancient_timestamp",
                                "description": f"Very old timestamp: {timestamp}",
                                "confidence": 0.8,
                                "severity": "medium"
                            })

                except (ValueError, TypeError):
                    pass

        # Check for unusual data sizes
        if 'size' in data or 'length' in data:
            size = data.get('size') or data.get('length')
            if isinstance(size, (int, float)):
                # Extremely large or small sizes
                if size > 10000000:  # 10MB
                    anomalies.append({
                        "type": "unusually_large",
                        "description": f"Unusually large data size: {size} bytes",
                        "confidence": 0.6,
                        "severity": "low"
                    })
                elif size < 10:  # Very small
                    anomalies.append({
                        "type": "unusually_small",
                        "description": f"Unusually small data size: {size} bytes",
                        "confidence": 0.4,
                        "severity": "low"
                    })

        # Check for suspicious URLs or domains
        text = self._extract_text_for_analysis(data)
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']
        for url in urls:
            domain = re.search(r'https?://([^/]+)', url)
            if domain:
                domain_name = domain.group(1).lower()
                if any(domain_name.endswith(tld) for tld in suspicious_tlds):
                    anomalies.append({
                        "type": "suspicious_domain",
                        "description": f"Suspicious domain detected: {domain_name}",
                        "confidence": 0.8,
                        "severity": "high",
                        "domain": domain_name
                    })

        return anomalies

    def _calculate_overall_confidence(self, patterns: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence score for the analysis"""
        if not patterns and not anomalies:
            return 0.0

        # Weight patterns by confidence and severity
        pattern_score = 0.0
        for pattern in patterns:
            weight = 1.0
            if pattern.get('severity') == 'high':
                weight = 3.0
            elif pattern.get('severity') == 'medium':
                weight = 2.0

            pattern_score += pattern.get('confidence', 0.0) * weight

        # Weight anomalies similarly
        anomaly_score = 0.0
        for anomaly in anomalies:
            weight = 1.0
            if anomaly.get('severity') == 'high':
                weight = 3.0
            elif anomaly.get('severity') == 'medium':
                weight = 2.0

            anomaly_score += anomaly.get('confidence', 0.0) * weight

        # Normalize
        total_score = pattern_score + anomaly_score
        max_possible = (len(patterns) * 3.0) + (len(anomalies) * 3.0)

        return min(1.0, total_score / max_possible) if max_possible > 0 else 0.0

    def predict_threats(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Predict potential threats based on indicators"""
        try:
            threats = []
            total_confidence = 0.0

            for indicator in indicators:
                # Analyze each indicator
                analysis = self.analyze_patterns(indicator)
                confidence = analysis.get('confidence', 0.0)

                if confidence > 0.3:  # Threshold for threat detection
                    threat = {
                        "indicator": indicator,
                        "threat_level": "high" if confidence > 0.7 else "medium" if confidence > 0.5 else "low",
                        "confidence": confidence,
                        "patterns": analysis.get('patterns', []),
                        "anomalies": analysis.get('anomalies', [])
                    }
                    threats.append(threat)

                total_confidence += confidence

            avg_confidence = total_confidence / len(indicators) if indicators else 0.0

            return {
                "threats": threats,
                "total_indicators": len(indicators),
                "detected_threats": len(threats),
                "average_confidence": avg_confidence,
                "overall_risk": "high" if avg_confidence > 0.6 else "medium" if avg_confidence > 0.3 else "low"
            }

        except Exception as e:
            logger.error(f"Failed to predict threats: {e}")
            return {"threats": [], "confidence": 0.0, "error": str(e)}

    def cluster_similar_patterns(self, data_points: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Cluster similar patterns using basic similarity metrics"""
        try:
            clusters: List[Dict[str, Any]] = []
            processed = set()

            for i, point1 in enumerate(data_points):
                if i in processed:
                    continue

                cluster = [point1]
                processed.add(i)

                # Find similar points
                for j, point2 in enumerate(data_points):
                    if j not in processed and self._calculate_similarity(point1, point2) > 0.7:
                        cluster.append(point2)
                        processed.add(j)

                if len(cluster) > 1:  # Only include clusters with multiple points
                    clusters.append({
                        "cluster_id": len(clusters),
                        "points": cluster,
                        "size": len(cluster),
                        "centroid": self._calculate_centroid(cluster)
                    })

            return {
                "clusters": clusters,
                "total_clusters": len(clusters),
                "clustered_points": sum(len(c['points']) for c in clusters),
                "unclustered_points": len(data_points) - sum(len(c['points']) for c in clusters)
            }

        except Exception as e:
            logger.error(f"Failed to cluster patterns: {e}")
            return {"clusters": [], "error": str(e)}

    def _calculate_similarity(self, point1: Dict[str, Any], point2: Dict[str, Any]) -> float:
        """Calculate similarity between two data points"""
        text1 = self._extract_text_for_analysis(point1)
        text2 = self._extract_text_for_analysis(point2)

        if not text1 or not text2:
            return 0.0

        # Simple Jaccard similarity of words
        words1 = set(re.findall(r'\b\w+\b', text1.lower()))
        words2 = set(re.findall(r'\b\w+\b', text2.lower()))

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    def _calculate_centroid(self, cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate centroid of a cluster"""
        if not cluster:
            return {}

        # Simple centroid based on common words
        all_texts = [self._extract_text_for_analysis(point) for point in cluster]
        all_words = [word for text in all_texts for word in re.findall(r'\b\w+\b', text.lower())]

        word_counts = Counter(all_words)
        common_words = [word for word, count in word_counts.most_common(5)]

        return {
            "common_words": common_words,
            "avg_text_length": sum(len(text) for text in all_texts) / len(all_texts),
            "cluster_theme": self._infer_cluster_theme(common_words)
        }

    def _infer_cluster_theme(self, common_words: List[str]) -> str:
        """Infer the theme of a cluster based on common words"""
        threat_keywords = {
            'phishing': ['login', 'password', 'account', 'verify', 'urgent'],
            'malware': ['virus', 'trojan', 'malware', 'infection', 'security'],
            'fraud': ['money', 'transfer', 'payment', 'scam', 'prize'],
            'espionage': ['secret', 'classified', 'intelligence', 'surveillance']
        }

        best_match = "general"
        best_score = 0

        for theme, keywords in threat_keywords.items():
            score = sum(1 for word in common_words if word in keywords)  # type: ignore
            if score > best_score:
                best_score = score
                best_match = theme

        return best_match