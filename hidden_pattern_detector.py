#!/usr/bin/env python3
"""
Hidden Pattern Detector Module
Advanced pattern recognition for intelligence analysis.
"""

import logging
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class HiddenPatternDetector:
    """Advanced hidden pattern detector for intelligence analysis"""

    def __init__(self):
        self.enabled = True
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'phone': r'\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b',
            'url': r'https?://[^\s]+',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'hash_md5': r'\b[a-fA-F0-9]{32}\b',
            'hash_sha1': r'\b[a-fA-F0-9]{40}\b',
            'hash_sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        logger.info("HiddenPatternDetector initialized with pattern recognition")

    def detect_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect hidden patterns in data"""
        if not self.enabled:
            return {"patterns_found": [], "confidence": 0.0}
        
        patterns_found = []
        text_content = self._extract_text_content(data)
        
        for pattern_name, pattern_regex in self.patterns.items():
            matches = re.findall(pattern_regex, text_content, re.IGNORECASE)
            if matches:
                patterns_found.append({
                    'type': pattern_name,
                    'matches': list(set(matches)),  # Remove duplicates
                    'count': len(matches),
                    'confidence': min(len(matches) * 0.1 + 0.5, 1.0)
                })
        
        # Calculate overall confidence
        overall_confidence = min(len(patterns_found) * 0.2, 1.0) if patterns_found else 0.0
        
        return {
            "patterns_found": patterns_found,
            "confidence": overall_confidence,
            "total_patterns": len(patterns_found),
            "analysis_timestamp": str(__import__('datetime').datetime.now())
        }

    def analyze_correlations(self, datasets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze correlations between datasets"""
        if not self.enabled or len(datasets) < 2:
            return {"correlations": [], "significance": 0.0}
        
        correlations = []
        
        # Extract patterns from all datasets
        all_patterns = []
        for i, dataset in enumerate(datasets):
            patterns = self.detect_patterns(dataset)
            all_patterns.append((i, patterns))
        
        # Find common patterns across datasets
        pattern_occurrences = defaultdict(list)
        
        for dataset_idx, pattern_data in all_patterns:
            for pattern in pattern_data['patterns_found']:
                pattern_type = pattern['type']
                for match in pattern['matches']:
                    pattern_occurrences[f"{pattern_type}:{match}"].append(dataset_idx)
        
        # Identify significant correlations
        for pattern_key, dataset_indices in pattern_occurrences.items():
            if len(dataset_indices) > 1:  # Pattern appears in multiple datasets
                pattern_type, pattern_value = pattern_key.split(':', 1)
                correlation_strength = len(dataset_indices) / len(datasets)
                
                correlations.append({
                    'pattern_type': pattern_type,
                    'pattern_value': pattern_value,
                    'datasets': dataset_indices,
                    'correlation_strength': correlation_strength,
                    'significance': correlation_strength * 0.8  # Adjusted significance
                })
        
        # Calculate overall significance
        overall_significance = min(len(correlations) * 0.15, 1.0) if correlations else 0.0
        
        return {
            "correlations": correlations,
            "significance": overall_significance,
            "total_correlations": len(correlations),
            "datasets_analyzed": len(datasets)
        }
    
    def _extract_text_content(self, data: Dict[str, Any]) -> str:
        """Extract text content from data structure for pattern analysis"""
        text_parts = []
        
        def extract_recursive(obj):
            if isinstance(obj, str):
                text_parts.append(obj)
            elif isinstance(obj, dict):
                for value in obj.values():
                    extract_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_recursive(item)
            elif obj is not None:
                text_parts.append(str(obj))
        
        extract_recursive(data)
        return ' '.join(text_parts)
    
    def add_custom_pattern(self, name: str, regex: str) -> bool:
        """Add a custom pattern for detection"""
        try:
            # Test the regex
            re.compile(regex)
            self.patterns[name] = regex
            logger.info(f"Added custom pattern '{name}': {regex}")
            return True
        except re.error as e:
            logger.error(f"Invalid regex pattern for '{name}': {e}")
            return False
    
    def get_pattern_statistics(self, data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistical analysis of patterns across multiple data points"""
        pattern_stats = Counter()
        total_analyzed = 0
        
        for data in data_list:
            patterns = self.detect_patterns(data)
            total_analyzed += 1
            
            for pattern in patterns['patterns_found']:
                pattern_stats[pattern['type']] += pattern['count']
        
        # Calculate pattern frequencies
        pattern_frequencies = {}
        for pattern_type, count in pattern_stats.items():
            pattern_frequencies[pattern_type] = {
                'total_occurrences': count,
                'frequency': count / total_analyzed if total_analyzed > 0 else 0,
                'avg_per_dataset': count / total_analyzed if total_analyzed > 0 else 0
            }
        
        return {
            'pattern_frequencies': pattern_frequencies,
            'total_datasets_analyzed': total_analyzed,
            'unique_pattern_types': len(pattern_stats),
            'most_common_pattern': pattern_stats.most_common(1)[0] if pattern_stats else None
        }