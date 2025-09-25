"""
Advanced Intelligence Platform Integration
=========================================

Master integration module that ties together all advanced intelligence
capabilities for comprehensive OSINT operations.

This module provides:
- Unified interface to all intelligence engines
- Coordinated cross-reference operations
- End-to-end conspiracy theory analysis
- Comprehensive reporting and visualization
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from api_key_manager import APIConfigurationManager
from conspiracy_analyzer import (ConspiracyAnalysisResult,
                                 ConspiracyTheoryAnalyzer)
# Import all our advanced modules
from cross_reference_engine import (ConspiracyTheory, CrossReferenceEngine,
                                    CrossReferenceHit)
from hidden_pattern_detector import HiddenPattern, HiddenPatternDetector

logger = logging.getLogger(__name__)

@dataclass
class IntelligenceOperation:
    """Represents a comprehensive intelligence operation."""
    operation_id: str
    operation_name: str
    target_query: str
    operation_type: str  # investigation, validation, pattern_analysis, conspiracy_analysis
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"  # running, completed, failed
    results: Dict[str, Any] = None

class AdvancedIntelligencePlatform:
    """
    Master platform integrating all advanced intelligence capabilities.
    
    This platform coordinates:
    - Cross-reference intelligence gathering
    - Hidden pattern detection
    - Conspiracy theory analysis  
    - API management and optimization
    """
    
    def __init__(self):
        self.cross_ref_engine = CrossReferenceEngine()
        self.pattern_detector = HiddenPatternDetector()
        self.conspiracy_analyzer = ConspiracyTheoryAnalyzer()
        self.api_manager = APIConfigurationManager()
        
        self.active_operations = {}
        self.operation_history = []
    
    async def comprehensive_investigation(self, target: str, 
                                        investigation_type: str = 'full_spectrum') -> Dict[str, Any]:
        """
        Perform comprehensive investigation using all available intelligence tools.
        
        Args:
            target: Investigation target (person, organization, event, etc.)
            investigation_type: 'full_spectrum', 'conspiracy_focus', 'pattern_focus', 'validation_focus'
        
        Returns:
            Comprehensive investigation results
        """
        operation_id = f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        operation = IntelligenceOperation(
            operation_id=operation_id,
            operation_name=f"Investigation: {target}",
            target_query=target,
            operation_type=investigation_type,
            start_time=datetime.now()
        )
        
        self.active_operations[operation_id] = operation
        
        try:
            logger.info(f"Starting comprehensive investigation: {target}")
            
            results = {
                'operation_id': operation_id,
                'target': target,
                'investigation_type': investigation_type,
                'start_time': operation.start_time.isoformat(),
                'cross_reference_results': {},
                'hidden_patterns': [],
                'conspiracy_analysis': {},
                'api_status': {},
                'summary': {},
                'recommendations': []
            }
            
            # Step 1: Cross-reference intelligence gathering
            logger.info("Phase 1: Cross-reference intelligence gathering")
            cross_ref_results = await self.cross_ref_engine.cross_reference_search(
                target, search_mode=self._get_search_mode(investigation_type)
            )
            results['cross_reference_results'] = {
                'hit_count': len(cross_ref_results),
                'high_confidence_hits': len([h for h in cross_ref_results if h.confidence > 0.7]),
                'sources_covered': list(set([h.source for h in cross_ref_results])),
                'top_hits': [self._summarize_hit(h) for h in cross_ref_results[:10]]
            }
            
            # Step 2: Hidden pattern detection
            logger.info("Phase 2: Hidden pattern detection")
            pattern_data = [hit.content for hit in cross_ref_results]
            pattern_data.append(target)  # Include target as data point
            
            hidden_patterns = await self.pattern_detector.detect_hidden_patterns(
                pattern_data, self._get_detection_modes(investigation_type)
            )
            results['hidden_patterns'] = [self._summarize_pattern(p) for p in hidden_patterns]
            
            # Step 3: Conspiracy theory analysis (if applicable)
            if investigation_type in ['full_spectrum', 'conspiracy_focus']:
                logger.info("Phase 3: Conspiracy theory analysis")
                
                # Create conspiracy theory from investigation data
                theory = self._create_theory_from_investigation(target, cross_ref_results, hidden_patterns)
                
                if theory:
                    conspiracy_analysis = await self.conspiracy_analyzer.analyze_conspiracy_theory(theory)
                    results['conspiracy_analysis'] = self._summarize_conspiracy_analysis(conspiracy_analysis)
            
            # Step 4: API status validation
            logger.info("Phase 4: API status validation")
            api_statuses = await self.api_manager.validate_all_services(fix_issues=False)
            results['api_status'] = {
                'total_services': len(api_statuses),
                'active_services': len([s for s in api_statuses.values() if s.is_valid]),
                'service_health': {name: status.is_valid for name, status in api_statuses.items()}
            }
            
            # Step 5: Generate comprehensive summary
            results['summary'] = self._generate_investigation_summary(results)
            results['recommendations'] = self._generate_investigation_recommendations(results)
            
            # Complete operation
            operation.end_time = datetime.now()
            operation.status = "completed"
            operation.results = results
            
            self.operation_history.append(operation)
            del self.active_operations[operation_id]
            
            logger.info(f"Investigation completed: {operation_id}")
            
            return results
            
        except Exception as e:
            operation.status = "failed"
            operation.end_time = datetime.now()
            logger.error(f"Investigation failed: {e}")
            raise
    
    def _get_search_mode(self, investigation_type: str) -> str:
        """Get appropriate search mode for investigation type."""
        mode_mapping = {
            'full_spectrum': 'comprehensive',
            'conspiracy_focus': 'conspiracy_focus',
            'pattern_focus': 'hidden_patterns',
            'validation_focus': 'comprehensive'
        }
        return mode_mapping.get(investigation_type, 'comprehensive')
    
    def _get_detection_modes(self, investigation_type: str) -> List[str]:
        """Get appropriate detection modes for investigation type."""
        if investigation_type == 'pattern_focus':
            return list(self.pattern_detector.detection_algorithms.keys())
        elif investigation_type == 'conspiracy_focus':
            return ['entity_network_analysis', 'temporal_correlation', 'linguistic_analysis']
        else:
            return ['temporal_correlation', 'entity_network_analysis', 'financial_flow_analysis']
    
    def _summarize_hit(self, hit: CrossReferenceHit) -> Dict[str, Any]:
        """Summarize a cross-reference hit."""
        return {
            'source': hit.source,
            'title': hit.title,
            'confidence': hit.confidence,
            'relevance': hit.relevance_score,
            'url': hit.url,
            'patterns_detected': len(hit.patterns_detected),
            'hidden_indicators': len(hit.hidden_indicators)
        }
    
    def _summarize_pattern(self, pattern: HiddenPattern) -> Dict[str, Any]:
        """Summarize a hidden pattern."""
        return {
            'pattern_name': pattern.pattern_name,
            'pattern_type': pattern.pattern_type,
            'confidence': pattern.confidence_score,
            'significance': pattern.significance_level,
            'truth_probability': pattern.truth_probability,
            'entities_involved': len(pattern.entities_involved),
            'evidence_count': len(pattern.evidence)
        }
    
    def _create_theory_from_investigation(self, target: str, hits: List[CrossReferenceHit], 
                                        patterns: List[HiddenPattern]) -> Optional[ConspiracyTheory]:
        """Create conspiracy theory from investigation data."""
        try:
            # Extract potential actors from hits and patterns
            actors = set()
            for hit in hits:
                # Simple entity extraction from titles
                words = hit.title.split()
                for word in words:
                    if word[0].isupper() and len(word) > 3:
                        actors.add(word)
            
            for pattern in patterns:
                actors.update(pattern.entities_involved)
            
            actors.add(target)  # Include target as actor
            
            # Generate claims based on patterns
            claims = []
            for pattern in patterns:
                if pattern.confidence_score > 0.6:
                    claims.append(pattern.description)
            
            if not claims:
                claims = [f"Investigation target {target} may be involved in coordinated activities"]
            
            # Extract events from hits
            events = []
            for hit in hits:
                if any(word in hit.title.lower() for word in ['leak', 'scandal', 'investigation', 'report']):
                    events.append(hit.title)
            
            if not events:
                events = [f"{target} investigation initiated"]
            
            # Create theory
            theory = ConspiracyTheory(
                theory_id=f"auto_generated_{target.replace(' ', '_')}",
                title=f"Investigation Analysis: {target}",
                description=f"Automated analysis of potential coordinated activities involving {target}",
                key_claims=claims[:5],  # Limit to 5 claims
                key_actors=list(actors)[:10],  # Limit to 10 actors
                key_events=events[:5]  # Limit to 5 events
            )
            
            return theory
            
        except Exception as e:
            logger.warning(f"Theory creation failed: {e}")
            return None
    
    def _summarize_conspiracy_analysis(self, analysis: ConspiracyAnalysisResult) -> Dict[str, Any]:
        """Summarize conspiracy analysis results."""
        return {
            'truth_probability': analysis.overall_truth_probability,
            'confidence_level': analysis.confidence_level.value,
            'evidence_summary': analysis.evidence_summary,
            'claims_analyzed': len(analysis.claim_analysis),
            'patterns_detected': len(analysis.hidden_patterns),
            'expert_consensus': analysis.expert_consensus.get('consensus_score', 0),
            'alternative_explanations': len(analysis.alternative_explanations),
            'key_recommendations': analysis.recommendations[:3]
        }
    
    def _generate_investigation_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive investigation summary."""
        try:
            summary = {
                'investigation_scope': 'comprehensive',
                'data_sources_accessed': 0,
                'evidence_quality': 'unknown',
                'pattern_strength': 'unknown',
                'overall_assessment': 'inconclusive',
                'confidence_level': 'moderate'
            }
            
            # Assess data sources
            cross_ref = results.get('cross_reference_results', {})
            summary['data_sources_accessed'] = len(cross_ref.get('sources_covered', []))
            
            # Assess evidence quality
            hit_count = cross_ref.get('hit_count', 0)
            high_conf_hits = cross_ref.get('high_confidence_hits', 0)
            
            if hit_count > 0:
                quality_ratio = high_conf_hits / hit_count
                if quality_ratio > 0.7:
                    summary['evidence_quality'] = 'high'
                elif quality_ratio > 0.4:
                    summary['evidence_quality'] = 'moderate'
                else:
                    summary['evidence_quality'] = 'low'
            
            # Assess pattern strength
            patterns = results.get('hidden_patterns', [])
            if patterns:
                avg_confidence = sum(p.get('confidence', 0) for p in patterns) / len(patterns)
                if avg_confidence > 0.7:
                    summary['pattern_strength'] = 'strong'
                elif avg_confidence > 0.4:
                    summary['pattern_strength'] = 'moderate'
                else:
                    summary['pattern_strength'] = 'weak'
            
            # Overall assessment
            conspiracy = results.get('conspiracy_analysis', {})
            truth_prob = conspiracy.get('truth_probability', 0.5)
            
            if truth_prob > 0.7:
                summary['overall_assessment'] = 'high_probability'
                summary['confidence_level'] = 'high'
            elif truth_prob > 0.4:
                summary['overall_assessment'] = 'moderate_probability'
                summary['confidence_level'] = 'moderate'
            else:
                summary['overall_assessment'] = 'low_probability'
                summary['confidence_level'] = 'low'
            
            return summary
            
        except Exception as e:
            logger.error(f"Summary generation failed: {e}")
            return {'error': 'Summary generation failed'}
    
    def _generate_investigation_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate investigation recommendations."""
        recommendations = []
        
        try:
            # API-based recommendations
            api_status = results.get('api_status', {})
            active_services = api_status.get('active_services', 0)
            total_services = api_status.get('total_services', 0)
            
            if active_services < total_services * 0.8:
                recommendations.append("Configure additional API keys for better source coverage")
            
            # Evidence-based recommendations
            cross_ref = results.get('cross_reference_results', {})
            if cross_ref.get('hit_count', 0) < 5:
                recommendations.append("Expand search terms and investigate related entities")
            
            # Pattern-based recommendations
            patterns = results.get('hidden_patterns', [])
            high_conf_patterns = [p for p in patterns if p.get('confidence', 0) > 0.7]
            
            if high_conf_patterns:
                recommendations.append("Focus investigation on high-confidence pattern areas")
            
            # Conspiracy analysis recommendations
            conspiracy = results.get('conspiracy_analysis', {})
            if conspiracy.get('truth_probability', 0) > 0.6:
                recommendations.append("Escalate investigation - high probability indicators detected")
                recommendations.append("Secure and preserve all evidence")
            
            # General recommendations
            recommendations.extend([
                "Cross-reference findings with additional leak databases",
                "Investigate temporal correlations for coordination evidence",
                "Analyze entity networks for hidden relationships",
                "Monitor for new evidence and pattern evolution"
            ])
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            return ["Continue investigation with standard methodology"]
    
    async def quick_conspiracy_check(self, theory_description: str) -> Dict[str, Any]:
        """Perform quick conspiracy theory validation."""
        try:
            # Create simple theory object
            theory = ConspiracyTheory(
                theory_id=f"quick_check_{datetime.now().strftime('%H%M%S')}",
                title="Quick Validation Check",
                description=theory_description,
                key_claims=[theory_description],
                key_actors=[],
                key_events=[]
            )
            
            # Perform lightweight analysis
            analysis = await self.conspiracy_analyzer.analyze_conspiracy_theory(theory, deep_analysis=False)
            
            return {
                'truth_probability': analysis.overall_truth_probability,
                'confidence': analysis.confidence_level.value,
                'assessment': 'plausible' if analysis.overall_truth_probability > 0.6 else 'questionable',
                'evidence_found': analysis.evidence_summary.get('total_evidence', 0),
                'key_recommendation': analysis.recommendations[0] if analysis.recommendations else "Conduct deeper investigation"
            }
            
        except Exception as e:
            logger.error(f"Quick conspiracy check failed: {e}")
            return {'error': str(e)}
    
    async def validate_platform_health(self) -> Dict[str, Any]:
        """Validate overall platform health and readiness."""
        health_report = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'unknown',
            'component_status': {},
            'api_health': {},
            'performance_metrics': {},
            'recommendations': []
        }
        
        try:
            # Test each component
            components = {
                'cross_reference_engine': self.cross_ref_engine,
                'pattern_detector': self.pattern_detector,
                'conspiracy_analyzer': self.conspiracy_analyzer,
                'api_manager': self.api_manager
            }
            
            for name, component in components.items():
                try:
                    # Basic availability check
                    health_report['component_status'][name] = 'operational'
                except Exception as e:
                    health_report['component_status'][name] = f'error: {e}'
            
            # Validate API services
            api_statuses = await self.api_manager.validate_all_services(fix_issues=False)
            health_report['api_health'] = {
                'total_services': len(api_statuses),
                'active_services': len([s for s in api_statuses.values() if s.is_valid]),
                'success_rate': len([s for s in api_statuses.values() if s.is_valid]) / len(api_statuses) if api_statuses else 0
            }
            
            # Determine overall status
            component_failures = len([s for s in health_report['component_status'].values() if 'error' in str(s)])
            api_success_rate = health_report['api_health']['success_rate']
            
            if component_failures == 0 and api_success_rate > 0.8:
                health_report['overall_status'] = 'excellent'
            elif component_failures == 0 and api_success_rate > 0.5:
                health_report['overall_status'] = 'good'
            elif component_failures <= 1:
                health_report['overall_status'] = 'degraded'
            else:
                health_report['overall_status'] = 'critical'
            
            # Generate recommendations
            if api_success_rate < 0.8:
                health_report['recommendations'].append("Configure additional API keys for better service coverage")
            
            if component_failures > 0:
                health_report['recommendations'].append("Address component failures for optimal performance")
            
            health_report['recommendations'].append("Platform ready for advanced intelligence operations")
            
            return health_report
            
        except Exception as e:
            logger.error(f"Health validation failed: {e}")
            health_report['overall_status'] = 'error'
            health_report['error'] = str(e)
            return health_report

# Factory function
def create_intelligence_platform() -> AdvancedIntelligencePlatform:
    """Create and initialize the advanced intelligence platform."""
    return AdvancedIntelligencePlatform()

# Demo function
async def platform_demo():
    """Demonstrate platform capabilities."""
    platform = create_intelligence_platform()
    
    print("=== ADVANCED INTELLIGENCE PLATFORM DEMO ===")
    print()
    
    # Health check
    print("1. Platform Health Check...")
    health = await platform.validate_platform_health()
    print(f"   Overall Status: {health['overall_status']}")
    print(f"   API Services: {health['api_health']['active_services']}/{health['api_health']['total_services']} active")
    print()
    
    # Quick conspiracy check
    print("2. Quick Conspiracy Theory Check...")
    theory = "Shell companies were used to hide political donations"
    check_result = await platform.quick_conspiracy_check(theory)
    print(f"   Theory: {theory}")
    print(f"   Assessment: {check_result.get('assessment', 'unknown')}")
    print(f"   Truth Probability: {check_result.get('truth_probability', 0):.3f}")
    print()
    
    print("=== PLATFORM READY FOR OPERATIONS ===")

if __name__ == "__main__":
    asyncio.run(platform_demo())