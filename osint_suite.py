#!/usr/bin/env python3
"""
OSINT Suite Core Module
========================

Unified OSINT intelligence gathering platform with web interface,
passive reconnaissance, and comprehensive analysis capabilities.
"""

import sys
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import core components
from api.api_server import app
from security.secrets_manager import secrets_manager
from security.api_key_manager import create_api_config_manager
from core.local_llm_engine import LocalLLMEngine
from reporting.reporting_engine import EnhancedReportingEngine
from reporting.report_scheduler import ReportScheduler
from realtime.realtime_feeds import RealTimeIntelligenceFeed
from utils.transport import get_tor_status, ProxiedTransport
from utils.osint_utils import OSINTUtils

# Import passive intelligence modules
from modules.passive_search import PassiveSearchIntelligence
from modules.web_scraper import WebScraper
from modules.search_engine_dorking import SearchEngineDorking
from modules.certificate_transparency import CertificateTransparency
from modules.wayback_machine import WaybackMachine
from modules.paste_site_monitor import PasteSiteMonitor
from modules.social_media_footprint import SocialMediaFootprint
from modules.github_search import GitHubSearch
from modules.passive_dns_enum import PassiveDNSEnum
from modules.whois_history import WhoisHistory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OSINTSuite:
    """
    Comprehensive OSINT Suite with web interface and passive intelligence gathering.
    """

    def __init__(self):
        """Initialize the OSINT Suite"""
        self.utils = OSINTUtils()
        self.transport = ProxiedTransport()
        self.api_manager = create_api_config_manager()

        # Initialize AI and reporting
        self.llm_engine = None
        self.reporting_engine = None
        self.report_scheduler = None
        self.realtime_feeds = None

        # Initialize passive intelligence modules
        self.passive_modules = {}

        # Initialize components
        self._initialize_components()
        self._initialize_passive_modules()

        logger.info("OSINT Suite initialized successfully")

    def _initialize_components(self):
        """Initialize core components"""
        try:
            # Initialize LLM engine if API key available
            openai_key = secrets_manager.get_secret("api_key_openai")
            if openai_key:
                self.llm_engine = LocalLLMEngine()
                logger.info("LLM engine initialized")
            else:
                logger.warning("No OpenAI API key found - LLM features disabled")

            # Initialize reporting system
            self.reporting_engine = EnhancedReportingEngine(ai_engine=self.llm_engine)
            self.report_scheduler = ReportScheduler(self.reporting_engine)
            logger.info("Reporting system initialized")

            # Initialize real-time feeds
            self.realtime_feeds = RealTimeIntelligenceFeed()
            logger.info("Real-time intelligence feeds initialized")

        except Exception as e:
            logger.error(f"Error initializing components: {e}")

    def _initialize_passive_modules(self):
        """Initialize passive intelligence gathering modules"""
        module_configs = {
            'passive_search': PassiveSearchIntelligence,
            'web_scraper': WebScraper,
            'search_engine_dorking': SearchEngineDorking,
            'certificate_transparency': CertificateTransparency,
            'wayback_machine': WaybackMachine,
            'paste_site_monitor': PasteSiteMonitor,
            'social_media_footprint': SocialMediaFootprint,
            'github_search': GitHubSearch,
            'passive_dns_enum': PassiveDNSEnum,
            'whois_history': WhoisHistory,
        }

        for module_name, module_class in module_configs.items():
            try:
                self.passive_modules[module_name] = module_class()
                logger.info(f"Initialized passive module: {module_name}")
            except Exception as e:
                logger.warning(f"Failed to initialize {module_name}: {e}")
                self.passive_modules[module_name] = None

    async def validate_system(self) -> Dict[str, Any]:
        """Validate system components and API keys"""
        logger.info("Validating OSINT Suite system...")

        results: Dict[str, Any] = {
            'timestamp': datetime.now().isoformat(),
            'api_keys': {},
            'tor_status': {},
            'passive_modules': {},
            'ai_status': {},
            'overall_health': 'unknown'
        }

        # Check API keys
        try:
            api_status = await self.api_manager.validate_all_services()
            results['api_keys'] = {
                service: {
                    'valid': status.is_valid,
                    'active': status.is_active,
                    'error': status.last_error
                }
                for service, status in api_status.items()
            }
        except Exception as e:
            results['api_keys'] = {'error': str(e)}

        # Check Tor status
        try:
            tor_status = get_tor_status()
            results['tor_status'] = tor_status
        except Exception as e:
            results['tor_status'] = {'error': str(e)}

        # Check passive modules
        for name, module in self.passive_modules.items():
            results['passive_modules'][name] = module is not None

        # Check AI status
        results['ai_status'] = {
            'llm_engine': self.llm_engine is not None,
            'reporting_engine': self.reporting_engine is not None,
            'realtime_feeds': self.realtime_feeds is not None
        }

        # Calculate overall health
        api_count = sum(1 for s in results['api_keys'].values()
                       if isinstance(s, dict) and s.get('valid'))
        passive_count = sum(results['passive_modules'].values())

        if api_count >= 3 and passive_count >= 8 and results['tor_status'].get('active'):
            results['overall_health'] = 'excellent'
        elif api_count >= 1 and passive_count >= 5:
            results['overall_health'] = 'good'
        elif passive_count >= 3:
            results['overall_health'] = 'fair'
        else:
            results['overall_health'] = 'poor'

        return results

    async def perform_passive_intelligence_gathering(
        self,
        target: str,
        target_type: str = 'domain',
        include_github: bool = True,
        include_wayback: bool = True,
        include_certificates: bool = True
    ) -> Dict[str, Any]:
        """
        Perform comprehensive passive intelligence gathering.

        Args:
            target: Target to investigate
            target_type: Type of target (domain, email, ip, etc.)
            include_github: Include GitHub search
            include_wayback: Include Wayback Machine
            include_certificates: Include certificate transparency

        Returns:
            Comprehensive intelligence report
        """
        logger.info(f"Starting passive intelligence gathering for {target} ({target_type})")

        results: Dict[str, Any] = {
            'target': target,
            'target_type': target_type,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'summary': {},
            'recommendations': []
        }

        # Passive search across multiple sources
        if self.passive_modules.get('passive_search'):
            try:
                search_results = self.passive_modules['passive_search'].analyze_target(target, target_type)
                results['sources']['passive_search'] = search_results
                logger.info("Passive search completed")
            except Exception as e:
                logger.error(f"Passive search failed: {e}")

        # Web scraping (if appropriate for target type)
        if self.passive_modules.get('web_scraper') and target_type in ['domain', 'url']:
            try:
                scrape_results = self.passive_modules['web_scraper'].scrape(target)
                results['sources']['web_scraping'] = scrape_results
                logger.info("Web scraping completed")
            except Exception as e:
                logger.error(f"Web scraping failed: {e}")

        # Search engine dorking
        if self.passive_modules.get('search_engine_dorking'):
            try:
                dork_results = self.passive_modules['search_engine_dorking'].dork(target)
                results['sources']['search_engine_dorking'] = dork_results
                logger.info("Search engine dorking completed")
            except Exception as e:
                logger.error(f"Search engine dorking failed: {e}")

        # Certificate transparency
        if include_certificates and self.passive_modules.get('certificate_transparency'):
            try:
                cert_results = self.passive_modules['certificate_transparency'].search(target)
                results['sources']['certificate_transparency'] = cert_results
                logger.info("Certificate transparency search completed")
            except Exception as e:
                logger.error(f"Certificate transparency search failed: {e}")

        # Wayback Machine
        if include_wayback and self.passive_modules.get('wayback_machine'):
            try:
                wayback_results = self.passive_modules['wayback_machine'].fetch_snapshots(target)
                results['sources']['wayback_machine'] = wayback_results
                logger.info("Wayback Machine search completed")
            except Exception as e:
                logger.error(f"Wayback Machine search failed: {e}")

        # Paste site monitoring
        if self.passive_modules.get('paste_site_monitor'):
            try:
                paste_results = self.passive_modules['paste_site_monitor'].search_pastes(target)
                results['sources']['paste_sites'] = paste_results
                logger.info("Paste site monitoring completed")
            except Exception as e:
                logger.error(f"Paste site monitoring failed: {e}")

        # Social media footprint
        if self.passive_modules.get('social_media_footprint'):
            try:
                social_results = self.passive_modules['social_media_footprint'].scrape_profiles(target)
                results['sources']['social_media'] = social_results
                logger.info("Social media footprint analysis completed")
            except Exception as e:
                logger.error(f"Social media footprint analysis failed: {e}")

        # GitHub search
        if include_github and self.passive_modules.get('github_search'):
            try:
                github_results = self.passive_modules['github_search'].search(target)
                results['sources']['github'] = github_results
                logger.info("GitHub search completed")
            except Exception as e:
                logger.error(f"GitHub search failed: {e}")

        # Passive DNS enumeration
        if self.passive_modules.get('passive_dns_enum'):
            try:
                dns_results = self.passive_modules['passive_dns_enum'].enumerate(target)
                results['sources']['passive_dns'] = dns_results
                logger.info("Passive DNS enumeration completed")
            except Exception as e:
                logger.error(f"Passive DNS enumeration failed: {e}")

        # WHOIS history
        if self.passive_modules.get('whois_history'):
            try:
                whois_results = self.passive_modules['whois_history'].get_history(target)
                results['sources']['whois_history'] = whois_results
                logger.info("WHOIS history analysis completed")
            except Exception as e:
                logger.error(f"WHOIS history analysis failed: {e}")

        # Generate AI-powered summary if available
        if self.llm_engine and results['sources']:
            try:
                ai_summary = await self.llm_engine.analyze_intelligence(results)
                results['summary']['ai_analysis'] = ai_summary
                logger.info("AI-powered analysis completed")
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")

        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)

        logger.info(f"Passive intelligence gathering completed for {target}")
        return results

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate investigation recommendations based on findings"""
        recommendations = []

        sources = results.get('sources', {})

        # Check for concerning findings
        if 'certificate_transparency' in sources and sources['certificate_transparency']:
            recommendations.append("Review SSL certificate history for potential domain impersonation")

        if 'paste_sites' in sources and sources['paste_sites']:
            recommendations.append("Investigate paste site leaks for sensitive information exposure")

        if 'github' in sources and sources['github']:
            recommendations.append("Review GitHub repositories for exposed credentials or sensitive code")

        if 'wayback_machine' in sources and sources['wayback_machine']:
            recommendations.append("Analyze historical website changes for security incidents")

        if 'social_media' in sources and sources['social_media']:
            recommendations.append("Monitor social media accounts for information disclosure")

        # General recommendations
        if len(sources) >= 5:
            recommendations.append("High-volume intelligence gathered - consider focused follow-up investigations")
        elif len(sources) <= 2:
            recommendations.append("Limited passive intelligence found - consider active reconnaissance if authorized")

        if not recommendations:
            recommendations.append("Continue monitoring target for new intelligence developments")

        return recommendations

    async def generate_custom_report(
        self,
        intelligence_data: Dict[str, Any],
        report_type: str = 'executive_summary',
        style: str = 'professional',
        length: str = 'medium',
        include_charts: bool = True,
        custom_sections: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate a custom report with specified parameters.

        Args:
            intelligence_data: Intelligence gathering results
            report_type: Type of report (executive_summary, technical, threat_assessment)
            style: Report style (professional, technical, executive)
            length: Report length (brief, medium, comprehensive)
            include_charts: Whether to include charts/visualizations
            custom_sections: Custom sections to include

        Returns:
            Generated report data
        """
        logger.info(f"Generating {report_type} report in {style} style ({length} length)")

        try:
            # Use the reporting engine to generate the report
            report_data: Dict[str, Any] = {
                'intelligence_data': intelligence_data,
                'report_type': report_type,
                'style': style,
                'length': length,
                'include_charts': include_charts,
                'custom_sections': custom_sections or [],
                'generated_at': datetime.now().isoformat(),
                'generated_by': 'OSINT Suite v2.0'
            }

            # Generate the report using the reporting engine
            if self.reporting_engine:
                if report_type == 'executive_summary':
                    report = self.reporting_engine.generate_executive_summary(intelligence_data)
                elif report_type == 'technical':
                    report = self.reporting_engine.generate_technical_report(intelligence_data)
                elif report_type == 'threat_assessment':
                    report = self.reporting_engine.generate_threat_assessment(intelligence_data)
                else:
                    report = self.reporting_engine.generate_custom_report(report_data)

                # Add metadata
                report.update({
                    'metadata': {
                        'report_type': report_type,
                        'style': style,
                        'length': length,
                        'sources_count': len(intelligence_data.get('sources', {})),
                        'generation_timestamp': datetime.now().isoformat()
                    }
                })

                logger.info(f"Report generated successfully: {report_type}")
                return report
            else:
                # Fallback report generation
                return self._generate_fallback_report(report_data)

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return {
                'error': str(e),
                'report_type': report_type,
                'generated_at': datetime.now().isoformat()
            }

    def _generate_fallback_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a basic report when the reporting engine is unavailable"""
        intelligence_data = report_data['intelligence_data']

        report: Dict[str, Any] = {
            'title': f"OSINT Intelligence Report - {intelligence_data.get('target', 'Unknown Target')}",
            'executive_summary': f"Passive intelligence gathering report for {intelligence_data.get('target', 'target')}.",
            'key_findings': [],
            'sources_analyzed': list(intelligence_data.get('sources', {}).keys()),
            'recommendations': intelligence_data.get('recommendations', []),
            'metadata': report_data
        }

        # Extract key findings from sources
        sources = intelligence_data.get('sources', {})
        for source_name, source_data in sources.items():
            if source_data:
                report['key_findings'].append(f"Intelligence gathered from {source_name}")

        return report

    async def start_web_interface(self, host: str = "127.0.0.1", port: int = 8000):
        """Start the web interface"""
        logger.info(f"Starting web interface on {host}:{port}")

        # Validate system before starting
        validation = await self.validate_system()
        health = validation.get('overall_health', 'unknown')

        if health in ['poor', 'unknown']:
            logger.warning(f"System health is {health} - some features may not work properly")

        logger.info(f"System health: {health}")
        logger.info(f"Active API services: {sum(1 for s in validation.get('api_keys', {}).values() if isinstance(s, dict) and s.get('valid', False))}")
        logger.info(f"Passive modules loaded: {sum(validation.get('passive_modules', {}).values())}")

        # Start the FastAPI server
        import uvicorn
        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)

        try:
            await server.serve()
        except KeyboardInterrupt:
            logger.info("Web interface stopped by user")
        except Exception as e:
            logger.error(f"Web interface error: {e}")

    def run_cli_interface(self):
        """Run the command-line interface"""
        from main import OSINTSuite as CLISuite
        cli_suite = CLISuite()
        cli_suite.main_menu()


# Global instance for easy access
osint_suite = OSINTSuite()


async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="OSINT Suite - Comprehensive Intelligence Platform")
    parser.add_argument("--web", action="store_true", help="Start web interface")
    parser.add_argument("--host", default="127.0.0.1", help="Web interface host")
    parser.add_argument("--port", type=int, default=8000, help="Web interface port")
    parser.add_argument("--cli", action="store_true", help="Start command-line interface")
    parser.add_argument("--validate", action="store_true", help="Validate system and exit")
    parser.add_argument("--tor-check", action="store_true", help="Check Tor connectivity")

    args = parser.parse_args()

    if args.validate:
        validation = await osint_suite.validate_system()
        print(f"System Health: {validation.get('overall_health', 'unknown').upper()}")
        print(f"API Keys: {sum(1 for s in validation.get('api_keys', {}).values() if isinstance(s, dict) and s.get('valid', False))}/18 active")
        print(f"Passive Modules: {sum(validation.get('passive_modules', {}).values())}/10 loaded")
        print(f"Tor Status: {validation.get('tor_status', {}).get('active', 'unknown')}")
        return

    if args.tor_check:
        from utils.transport import get_tor_status
        tor_status = get_tor_status()
        print(f"Tor Active: {tor_status.get('active', False)}")
        print(f"Tor IP: {tor_status.get('ip', 'unknown')}")
        return

    if args.web:
        await osint_suite.start_web_interface(args.host, args.port)
    elif args.cli:
        osint_suite.run_cli_interface()
    else:
        print("OSINT Suite v2.0")
        print("Use --web to start web interface or --cli for command line")
        print("Use --validate to check system status")


if __name__ == "__main__":
    asyncio.run(main())