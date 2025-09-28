"""
RapidAPI OSINT Integration Module
Provides access to various free RapidAPI services for OSINT gathering
"""

from typing import Dict, List, Optional, Any
from utils.osint_utils import OSINTUtils


class RapidAPIManager(OSINTUtils):
    """Manager for RapidAPI OSINT services"""

    def __init__(self):
        super().__init__()
        self.rapidapi_key = "cd3ad0cae1mshc965b142654a663p1285f9jsn3a93297c8238"
        self.base_headers = {
            'X-RapidAPI-Key': self.rapidapi_key,
            'X-RapidAPI-Host': '',
            'Content-Type': 'application/json'
        }

    def _make_rapidapi_request(self, host: str, endpoint: str, params: Optional[Dict] = None, method: str = 'GET') -> Optional[Dict]:
        """Make a request to RapidAPI service"""
        headers = self.base_headers.copy()
        headers['X-RapidAPI-Host'] = host

        url = f"https://{host}{endpoint}"

        try:
            response = self.make_request(url, headers=headers, params=params)
            if response and response.status_code == 200:
                return response.json()
            else:
                self.logger.warning(f"RapidAPI request failed: {response.status_code if response else 'No response'}")
                return None
        except Exception as e:
            self.logger.error(f"RapidAPI request error: {e}")
            return None

    def search_hunter_email_finder(self, domain: str, first_name: Optional[str] = None, last_name: Optional[str] = None) -> List[Dict]:
        """Find email addresses using Hunter.io via RapidAPI"""
        params = {'domain': domain}
        if first_name:
            params['first_name'] = first_name
        if last_name:
            params['last_name'] = last_name

        result = self._make_rapidapi_request(
            'hunter-email-finder.p.rapidapi.com',
            '/v2/email-finder',
            params=params
        )

        if result and 'data' in result:
            return [result['data']]
        return []

    def search_clearbit_company(self, domain: str) -> Optional[Dict]:
        """Get company information using Clearbit via RapidAPI"""
        result = self._make_rapidapi_request(
            'clearbit-company-data.p.rapidapi.com',
            '/company',
            {'domain': domain}
        )

        return result

    def search_pipl_person(self, email: Optional[str] = None, phone: Optional[str] = None,
                          name: Optional[str] = None, address: Optional[str] = None) -> Optional[Dict]:
        """Search for person information using Pipl via RapidAPI"""
        params = {}
        if email:
            params['email'] = email
        if phone:
            params['phone'] = phone
        if name:
            params['name'] = name
        if address:
            params['address'] = address

        if not params:
            return None

        result = self._make_rapidapi_request(
            'pipl-irrevocable-data.p.rapidapi.com',
            '/search',
            params
        )

        return result

    def search_zoominfo_company(self, company_name: str) -> Optional[Dict]:
        """Search for company information using ZoomInfo via RapidAPI"""
        result = self._make_rapidapi_request(
            'zoominfo1.p.rapidapi.com',
            '/company',
            {'company': company_name}
        )

        return result

    def search_fullcontact_person(self, email: str) -> Optional[Dict]:
        """Get person information using FullContact via RapidAPI"""
        result = self._make_rapidapi_request(
            'fullcontact1.p.rapidapi.com',
            '/person',
            {'email': email}
        )

        return result

    def search_ipinfo_geolocation(self, ip: str) -> Optional[Dict]:
        """Get IP geolocation using IPInfo via RapidAPI"""
        result = self._make_rapidapi_request(
            'ipinfo-geolocation.p.rapidapi.com',
            '/json',
            {'ip': ip}
        )

        return result

    def search_domain_whois(self, domain: str) -> Optional[Dict]:
        """Get WHOIS information using WhoisXML API via RapidAPI"""
        result = self._make_rapidapi_request(
            'whoisxmlapi-whois-service-v2.p.rapidapi.com',
            '/api/v2/whois',
            {'domain': domain}
        )

        return result

    def search_social_media_profiles(self, username: str) -> List[Dict]:
        """Search for social media profiles using SocialProfiles API via RapidAPI"""
        result = self._make_rapidapi_request(
            'socialprofiles.p.rapidapi.com',
            '/api/search',
            {'q': username}
        )

        if result and 'profiles' in result:
            return result['profiles']
        return []

    def search_pastebin_monitor(self, query: str) -> List[Dict]:
        """Monitor Pastebin for leaked information via RapidAPI"""
        result = self._make_rapidapi_request(
            'pastebin-data.p.rapidapi.com',
            '/api/search',
            {'q': query}
        )

        if result and 'pastes' in result:
            return result['pastes']
        return []

    def search_darkweb_mentions(self, query: str) -> List[Dict]:
        """Search dark web mentions via RapidAPI"""
        result = self._make_rapidapi_request(
            'dark-web-monitor.p.rapidapi.com',
            '/api/search',
            {'q': query}
        )

        if result and 'mentions' in result:
            return result['mentions']
        return []

    def search_cyber_news(self, query: str, limit: int = 10) -> List[Dict]:
        """Search cybersecurity news via RapidAPI"""
        result = self._make_rapidapi_request(
            'cyber-security-news.p.rapidapi.com',
            '/api/news',
            {'q': query, 'limit': limit}
        )

        if result and 'articles' in result:
            return result['articles']
        return []

    def search_threat_intelligence(self, indicator: str) -> Optional[Dict]:
        """Get threat intelligence for indicators via RapidAPI"""
        result = self._make_rapidapi_request(
            'threat-intelligence.p.rapidapi.com',
            '/api/lookup',
            {'indicator': indicator}
        )

        return result

    def search_crypto_wallet(self, address: str) -> Optional[Dict]:
        """Get cryptocurrency wallet information via RapidAPI"""
        result = self._make_rapidapi_request(
            'crypto-wallet-info.p.rapidapi.com',
            '/api/wallet',
            {'address': address}
        )

        return result

    def search_job_postings(self, company: str) -> List[Dict]:
        """Search for job postings from a company via RapidAPI"""
        result = self._make_rapidapi_request(
            'job-search-api.p.rapidapi.com',
            '/api/jobs',
            {'company': company}
        )

        if result and 'jobs' in result:
            return result['jobs']
        return []

    def search_court_records(self, name: str) -> List[Dict]:
        """Search court records via RapidAPI"""
        result = self._make_rapidapi_request(
            'court-records-search.p.rapidapi.com',
            '/api/search',
            {'name': name}
        )

        if result and 'records' in result:
            return result['records']
        return []

    def search_professional_networks(self, name: str, company: Optional[str] = None) -> List[Dict]:
        """Search professional networks for profiles via RapidAPI"""
        params = {'name': name}
        if company:
            params['company'] = company

        result = self._make_rapidapi_request(
            'professional-network-search.p.rapidapi.com',
            '/api/search',
            params
        )

        if result and 'profiles' in result:
            return result['profiles']
        return []


class RapidAPIOSINTModule(OSINTUtils):
    """Main RapidAPI OSINT integration module"""

    def __init__(self):
        super().__init__()
        self.rapidapi = RapidAPIManager()

    def comprehensive_person_search(self, email: Optional[str] = None, phone: Optional[str] = None,
                                  name: Optional[str] = None, username: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive person search using multiple RapidAPI services"""
        results: Dict[str, Any] = {
            'email': email,
            'phone': phone,
            'name': name,
            'username': username,
            'sources': {}
        }

        # Pipl person search
        if email or phone or name:
            pipl_result = self.rapidapi.search_pipl_person(email, phone, name)
            if pipl_result:
                results['sources']['pipl'] = pipl_result

        # FullContact for email
        if email:
            fullcontact_result = self.rapidapi.search_fullcontact_person(email)
            if fullcontact_result:
                results['sources']['fullcontact'] = fullcontact_result

        # Social media profiles
        if username:
            social_profiles = self.rapidapi.search_social_media_profiles(username)
            if social_profiles:
                results['sources']['social_media'] = social_profiles

        return results

    def comprehensive_company_search(self, domain: str, company_name: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive company search using multiple RapidAPI services"""
        results: Dict[str, Any] = {
            'domain': domain,
            'company_name': company_name,
            'sources': {}
        }

        # Clearbit company info
        clearbit_result = self.rapidapi.search_clearbit_company(domain)
        if clearbit_result:
            results['sources']['clearbit'] = clearbit_result

        # ZoomInfo company search
        if company_name:
            zoominfo_result = self.rapidapi.search_zoominfo_company(company_name)
            if zoominfo_result:
                results['sources']['zoominfo'] = zoominfo_result

        # Hunter.io email finder
        hunter_emails = self.rapidapi.search_hunter_email_finder(domain)
        if hunter_emails:
            results['sources']['hunter_emails'] = hunter_emails

        # Job postings
        if company_name:
            jobs = self.rapidapi.search_job_postings(company_name)
            if jobs:
                results['sources']['job_postings'] = jobs

        return results

    def comprehensive_domain_search(self, domain: str) -> Dict[str, Any]:
        """Comprehensive domain search using multiple RapidAPI services"""
        results: Dict[str, Any] = {
            'domain': domain,
            'sources': {}
        }

        # WHOIS information
        whois_result = self.rapidapi.search_domain_whois(domain)
        if whois_result:
            results['sources']['whois'] = whois_result

        # Company information from domain
        company_result = self.rapidapi.search_clearbit_company(domain)
        if company_result:
            results['sources']['company'] = company_result

        # Hunter.io email finder
        hunter_emails = self.rapidapi.search_hunter_email_finder(domain)
        if hunter_emails:
            results['sources']['hunter_emails'] = hunter_emails

        return results

    def threat_intelligence_lookup(self, indicator: str) -> Dict[str, Any]:
        """Comprehensive threat intelligence lookup"""
        results: Dict[str, Any] = {
            'indicator': indicator,
            'sources': {}
        }

        # Threat intelligence
        threat_result = self.rapidapi.search_threat_intelligence(indicator)
        if threat_result:
            results['sources']['threat_intel'] = threat_result

        # If it's an IP, get geolocation
        if self._is_ip_address(indicator):
            geo_result = self.rapidapi.search_ipinfo_geolocation(indicator)
            if geo_result:
                results['sources']['geolocation'] = geo_result

        # If it's a crypto address, get wallet info
        if self._is_crypto_address(indicator):
            wallet_result = self.rapidapi.search_crypto_wallet(indicator)
            if wallet_result:
                results['sources']['crypto_wallet'] = wallet_result

        return results

    def _is_ip_address(self, string: str) -> bool:
        """Check if string is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(string)
            return True
        except ValueError:
            return False

    def _is_crypto_address(self, string: str) -> bool:
        """Check if string is a cryptocurrency address"""
        # Basic checks for common crypto address formats
        if len(string) < 20:
            return False

        # Bitcoin addresses start with 1, 3, or bc1
        if string.startswith(('1', '3', 'bc1')) and 26 <= len(string) <= 62:
            return True

        # Ethereum addresses start with 0x
        if string.startswith('0x') and len(string) == 42:
            return True

        return False