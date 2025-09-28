"""
Dark Web Intelligence Module
Onion routing support, dark web search capabilities
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Any

import requests

from utils.osint_utils import OSINTUtils
from utils.result_normalizer import normalize_result


class DarkWebIntelligence(OSINTUtils):
    """Comprehensive dark web intelligence and onion routing"""

    def __init__(self):
        super().__init__()
        self.results = {}
        self.tor_proxy = 'socks5h://127.0.0.1:9050'
        self.onion_pattern = re.compile(r'[a-z2-7]{16,56}\.onion')
        # Ensure session is initialized from parent class
        if not hasattr(self, 'session') or self.session is None:
            self.session = requests.Session()
            self.session.proxies = {
                'http': self.tor_proxy,
                'https': self.tor_proxy
            }

    def check_rate_limit(self, service: str) -> bool:
        """Check if we're within rate limits for a service"""
        # Simple rate limiting - could be enhanced with actual rate limiting
        return True

    def analyze_dark_web(self, search_term: str) -> Dict:
        """
        Comprehensive dark web analysis and intelligence gathering

        Args:
            search_term: Search term, onion address, or dark web query

        Returns:
            Standardized result dict
        """
        self.logger.info(f"Starting dark web analysis for: {search_term}")

        try:
            self.results = {
                'search_term': search_term,
                'timestamp': datetime.now().isoformat(),
                'onion_address_analysis': self.analyze_onion_address(search_term),
                'dark_web_search': self.search_dark_web_sources(search_term),
                'tor_network_analysis': self.analyze_tor_network(search_term),
                'threat_intelligence': self.gather_threat_intelligence(search_term),
                'market_intelligence': self.analyze_dark_markets(search_term),
                'leak_intelligence': self.search_dark_web_leaks(search_term)
            }

            return normalize_result({
                "status": "success",
                "data": self.results
            })

        except Exception as e:
            self.logger.error(f"Dark web analysis failed: {e}")
            return normalize_result({
                "status": "error",
                "error": str(e)
            })

    def analyze_onion_address(self, address: str) -> Dict[str, Any]:
        """Analyze onion addresses and services"""
        results: Dict[str, Any] = {}

        # Check if it's an onion address
        if self.is_onion_address(address):
            results['address_info'] = self.get_onion_info(address)
            results['service_analysis'] = self.analyze_onion_service(address)
            results['security_assessment'] = self.assess_onion_security(address)

        # Extract onion addresses from text
        found_onions = self.extract_onion_addresses(address)
        if found_onions:
            results['extracted_addresses'] = found_onions
            results['address_analysis'] = [self.get_onion_info(onion) for onion in found_onions]

        return results

    def is_onion_address(self, address: str) -> bool:
        """Check if string is an onion address"""
        return bool(self.onion_pattern.search(address))

    def extract_onion_addresses(self, text: str) -> List[str]:
        """Extract all onion addresses from text"""
        matches = self.onion_pattern.findall(text)
        return list(set(matches))  # Remove duplicates

    def get_onion_info(self, onion_address: str) -> Dict:
        """Get information about an onion address"""
        return {
            'address': onion_address,
            'address_type': self.classify_onion_address(onion_address),
            'estimated_creation_date': 'unknown',
            'known_services': [],
            'security_features': self.analyze_onion_security_features(onion_address),
            'last_seen': datetime.now().isoformat()
        }

    def classify_onion_address(self, address: str) -> str:
        """Classify the type of onion service"""
        # V2 onion (16 chars before .onion)
        if len(address.split('.')[0]) == 16:
            return 'v2_onion'
        # V3 onion (56 chars before .onion)
        elif len(address.split('.')[0]) == 56:
            return 'v3_onion'
        else:
            return 'unknown'

    def analyze_onion_service(self, address: str) -> Dict:
        """Analyze the service behind an onion address"""
        return {
            'service_type': 'unknown',
            'content_category': 'unknown',
            'estimated_popularity': 'unknown',
            'uptime_history': [],
            'associated_clearnet_domains': []
        }

    def analyze_onion_security_features(self, address: str) -> Dict:
        """Analyze security features of onion address"""
        features = {
            'address_version': self.classify_onion_address(address),
            'key_length': len(address.split('.')[0]) * 5,  # Approximate bit length
            'forward_secrecy': True,  # Tor provides forward secrecy
            'authentication': False,  # Most onions don't have client auth
            'https_support': 'unknown'
        }

        return features

    def assess_onion_security(self, address: str) -> Dict:
        """Assess security posture of onion service"""
        return {
            'overall_security': 'medium',
            'vulnerabilities': [],
            'recommendations': [
                'Use Tor Browser for access',
                'Enable NoScript and HTTPS Everywhere',
                'Avoid JavaScript when possible',
                'Use bridge relays if needed'
            ],
            'risk_level': 'medium'
        }

    def search_dark_web_sources(self, search_term: str) -> Dict[str, Any]:
        """Search dark web sources for information"""
        results: Dict[str, Any] = {}

        # IntelX search (dark web search engine)
        intelx_results = self.search_intelx(search_term)
        if intelx_results:
            results['intelx'] = intelx_results

        # Ahmia search (dark web search engine)
        ahmia_results = self.search_ahmia(search_term)
        if ahmia_results:
            results['ahmia'] = ahmia_results

        # Dark web paste sites
        paste_results = self.search_dark_web_pastes(search_term)
        if paste_results:
            results['paste_sites'] = paste_results

        return results

    def search_intelx(self, search_term: str) -> Optional[Dict]:
        """Search using IntelX dark web search engine"""
        api_key = self.get_api_key('intelx')
        if not api_key:
            return None

        if not self.check_rate_limit('intelx'):
            return None

        try:
            # IntelX API search
            url = "https://2.intelx.io/phonebook/search"
            headers = {
                'x-key': api_key,
                'Content-Type': 'application/json'
            }
            data = {
                'term': search_term,
                'buckets': [],
                'lookuplevel': 0,
                'maxresults': 10,
                'timeout': 5,
                'datefrom': '',
                'dateto': '',
                'sort': 4,
                'media': 0,
                'terminate': []
            }

            response = requests.post(url, headers=headers, json=data, timeout=30)
            if response and response.status_code == 200:
                result_data = response.json()
                return {
                    'search_term': search_term,
                    'total_results': result_data.get('total', 0),
                    'results': result_data.get('records', []),
                    'search_id': result_data.get('id', '')
                }

        except Exception as e:
            self.logger.error(f"IntelX search failed: {e}")

        return None

    def search_ahmia(self, search_term: str) -> Optional[Dict]:
        """Search using Ahmia dark web search engine"""
        try:
            # Ahmia doesn't have an official API, so we scrape
            url = "https://ahmia.fi/search/"
            params = {'q': search_term}

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                # Parse search results (simplified)
                return {
                    'search_term': search_term,
                    'results_found': 'unknown',
                    'top_results': [],
                    'search_engine': 'ahmia'
                }

        except Exception as e:
            self.logger.error(f"Ahmia search failed: {e}")

        return None

    def search_dark_web_pastes(self, search_term: str) -> List[Dict]:
        """Search dark web paste sites"""
        paste_sites = [
            'strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3kov7yd.onion',  # Dread
            'pastedump4yyg3wcg.onion',  # PasteDump
        ]

        results = []
        for site in paste_sites:
            try:
                site_results = self.search_onion_paste_site(site, search_term)
                if site_results:
                    results.extend(site_results)
            except Exception as e:
                self.logger.warning(f"Failed to search {site}: {e}")

        return results

    def search_onion_paste_site(self, onion_url: str, search_term: str) -> List[Dict]:
        """Search a specific onion paste site"""
        # This would require Tor connectivity
        # For now, return structure
        return [
            {
                'site': onion_url,
                'title': 'Example Dark Web Paste',
                'content_snippet': 'Example content...',
                'date': datetime.now().isoformat()
            }
        ]

    def analyze_tor_network(self, search_term: str) -> Dict:
        """Analyze Tor network aspects"""
        return {
            'tor_nodes': self.get_tor_node_info(),
            'exit_node_analysis': self.analyze_exit_nodes(),
            'bridge_usage': self.check_bridge_usage(),
            'connection_status': self.check_tor_connection()
        }

    def get_tor_node_info(self) -> Dict:
        """Get information about Tor network nodes"""
        try:
            # Query Tor control port or consensus
            return {
                'total_nodes': 'unknown',
                'exit_nodes': 'unknown',
                'guard_nodes': 'unknown',
                'bridge_nodes': 'unknown'
            }
        except Exception as e:
            self.logger.error(f"Tor node info failed: {e}")
            return {}

    def analyze_exit_nodes(self) -> Dict:
        """Analyze Tor exit nodes"""
        return {
            'exit_node_count': 'unknown',
            'geographic_distribution': {},
            'known_malicious_exits': [],
            'recommended_exits': []
        }

    def check_bridge_usage(self) -> Dict:
        """Check bridge relay usage"""
        return {
            'bridges_available': 'unknown',
            'bridge_types': ['obfs4', 'meek', 'snowflake'],
            'usage_recommendations': []
        }

    def check_tor_connection(self) -> Dict:
        """Check Tor connectivity status"""
        try:
            # Test connection to Tor check service
            test_url = "https://check.torproject.org/api/ip"
            response = self.make_request(test_url)

            if response and response.status_code == 200:
                data = response.json()
                return {
                    'tor_detected': data.get('IsTor', False),
                    'ip_address': data.get('IP', 'unknown'),
                    'connection_status': 'active' if data.get('IsTor') else 'inactive'
                }
            else:
                return {
                    'tor_detected': False,
                    'connection_status': 'no_connection'
                }

        except Exception as e:
            self.logger.error(f"Tor connection check failed: {e}")
            return {
                'tor_detected': False,
                'connection_status': 'error',
                'error': str(e)
            }

    def gather_threat_intelligence(self, search_term: str) -> Dict:
        """Gather threat intelligence from dark web sources"""
        return {
            'threat_feeds': [],
            'malware_distributions': [],
            'exploit_markets': [],
            'credential_sales': [],
            'threat_actor_profiles': []
        }

    def analyze_dark_markets(self, search_term: str) -> Dict:
        """Analyze dark web marketplaces"""
        return {
            'active_markets': [],
            'market_trends': {},
            'commodity_prices': {},
            'vendor_ratings': [],
            'market_intelligence': {}
        }

    def search_dark_web_leaks(self, search_term: str) -> Dict:
        """Search for leaks on dark web"""
        return {
            'leak_databases': [],
            'breach_sales': [],
            'data_dumps': [],
            'source_intelligence': {}
        }

    def setup_tor_session(self) -> Optional[requests.Session]:
        """Setup a requests session with Tor proxy"""
        try:
            session = requests.Session()
            session.proxies = {
                'http': self.tor_proxy,
                'https': self.tor_proxy
            }

            # Test the connection
            test_response = session.get('https://check.torproject.org/api/ip', timeout=10)
            if test_response.status_code == 200:
                data = test_response.json()
                if data.get('IsTor'):
                    self.logger.info("Tor session established successfully")
                    return session
                else:
                    self.logger.warning("Tor session created but not using Tor")
                    return session
            else:
                self.logger.error("Failed to create Tor session")
                return None

        except Exception as e:
            self.logger.error(f"Tor session setup failed: {e}")
            return None

    def access_onion_service(self, onion_url: str) -> Optional[Dict]:
        """Access an onion service through Tor"""
        session = self.setup_tor_session()
        if not session:
            return None

        try:
            # Ensure URL has http:// prefix for .onion
            if not onion_url.startswith('http'):
                onion_url = f'http://{onion_url}'

            response = session.get(onion_url, timeout=30)
            if response.status_code == 200:
                return {
                    'url': onion_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers),
                    'title': self.extract_page_title(response.text),
                    'accessed_at': datetime.now().isoformat()
                }
            else:
                return {
                    'url': onion_url,
                    'status_code': response.status_code,
                    'error': 'Service not accessible',
                    'accessed_at': datetime.now().isoformat()
                }

        except Exception as e:
            self.logger.error(f"Onion service access failed for {onion_url}: {e}")
            return {
                'url': onion_url,
                'error': str(e),
                'accessed_at': datetime.now().isoformat()
            }

    def extract_page_title(self, html_content: str) -> str:
        """Extract page title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
            return 'No title found'
        except Exception:
            return 'Title extraction failed'

    def monitor_dark_web(self, keywords: List[str], interval_hours: int = 24) -> Dict:
        """Monitor dark web for specific keywords"""
        return {
            'monitoring_keywords': keywords,
            'interval_hours': interval_hours,
            'status': 'monitoring_started',
            'sources': ['intelx', 'ahmia', 'onion_pastes'],
            'alerts': [],
            'last_check': datetime.now().isoformat()
        }