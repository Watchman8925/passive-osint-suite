"""
Domain Reconnaissance Module
Comprehensive passive domain analysis
"""

from datetime import datetime

import dns.resolver
import tldextract
import whois

from utils.osint_utils import OSINTUtils


class DomainRecon(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def analyze_domain(self, domain):
        """Comprehensive domain analysis"""
        self.logger.info(f"Starting domain analysis for: {domain}")

        if not self.validate_input(domain, 'domain'):
            self.logger.error(f"Invalid domain format: {domain}")
            return {"status": "error", "error": f"Invalid domain format: {domain}"}

        try:
            self.results = {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'whois_info': self.get_whois_info(domain),
                'dns_records': self.get_dns_records(domain),
                'subdomains': self.find_subdomains(domain),
                'security_info': self.get_security_info(domain),
                'threat_intel': self.get_threat_intelligence(domain),
                'certificate_info': self.get_certificate_info(domain),
                'technology_stack': self.get_technology_stack(domain),
                'social_presence': self.find_social_presence(domain)
            }

            return {"status": "success", "data": self.results}

        except Exception as e:
            self.logger.error(f"Domain analysis failed: {e}")
            return {"status": "error", "error": str(e)}

    def get_whois_info(self, domain):
        """Get WHOIS information (supports both python-whois and whois.query)."""
        try:
            self.logger.info(f"Getting WHOIS info for {domain}")
            w = whois.whois(domain)

            whois_data = {
                "registrar": str(w.registrar) if w.registrar else None,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": (
                    str(w.expiration_date) if w.expiration_date else None
                ),
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "emails": w.emails if w.emails else [],
                "country": str(w.country) if w.country else None,
                "org": str(w.org) if w.org else None,
            }

            return whois_data
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {e}")
            return {'error': str(e)}

    def get_dns_records(self, domain):
        """Get DNS records (prefers secure DoH via Tor, falls back to system DNS)."""
        dns_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                dns_records[record_type] = []

        return dns_records

    def get_basic_dns_info(self, domain):
        """Lightweight DNS summary for quick terminal checks (A/AAAA/MX/NS/TXT)."""
        info = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                vals = self.resolve_domain_secure(domain, rtype)
                if not vals:
                    # fallback
                    answers = dns.resolver.resolve(domain, rtype)
                    vals = [str(a) for a in answers]
                info[rtype] = [str(v) for v in (vals or [])][:10]
            except Exception as e:
                self.logger.debug(f"Basic DNS {rtype} failed: {e}")
                info[rtype] = []
        return info

    def find_subdomains(self, domain):
        """Find subdomains using various sources"""
        subdomains = set()

        # Using Certificate Transparency logs via crt.sh
        subdomains.update(self.get_subdomains_crtsh(domain))

        # Using SecurityTrails API
        subdomains.update(self.get_subdomains_securitytrails(domain))

        # Using VirusTotal API
        subdomains.update(self.get_subdomains_virustotal(domain))

        return list(subdomains)

    def get_subdomains_crtsh(self, domain):
        """Get subdomains from crt.sh"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.make_request(url)
            if response:
                data = response.json()
                for cert in data:
                    name_value = cert.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and domain in subdomain:
                            subdomains.add(subdomain)
        except Exception as e:
            self.logger.error(f"crt.sh lookup failed: {e}")

        return subdomains

    def get_subdomains_securitytrails(self, domain):
        """Get subdomains from SecurityTrails"""
        subdomains = set()
        api_key = self.get_api_key('SECURITYTRAILS_API_KEY')

        if not api_key:
            return subdomains

        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {'APIKEY': api_key}
            response = self.make_request(url, headers=headers)

            if response:
                data = response.json()
                for subdomain in data.get('subdomains', []):
                    subdomains.add(f"{subdomain}.{domain}")

        except Exception as e:
            self.logger.error(f"SecurityTrails lookup failed: {e}")

        return subdomains

    def get_subdomains_virustotal(self, domain):
        """Get subdomains from VirusTotal"""
        subdomains = set()
        api_key = self.get_api_key('VIRUSTOTAL_API_KEY')

        if not api_key:
            return subdomains

        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": api_key, "domain": domain}
            response = self.make_request(url, params=params)

            if response:
                data = response.json()
                for subdomain in data.get('subdomains', []):
                    subdomains.add(subdomain)

        except Exception as e:
            self.logger.error(f"VirusTotal lookup failed: {e}")

        return subdomains

    def get_security_info(self, domain):
        """Get security information"""
        security_info = {
            'shodan_data': self.get_shodan_info(domain),
            'greynoise_data': self.get_greynoise_info(domain),
            'abuse_data': self.get_abuse_info(domain)
        }
        return security_info

    def get_shodan_info(self, domain):
        """Get Shodan information"""
        api_key = self.get_api_key('SHODAN_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            import shodan
            api = shodan.Shodan(api_key)
            results = api.search(f'hostname:{domain}')

            shodan_data = {
                'total_results': results['total'],
                'hosts': []
            }

            for result in results['matches'][:5]:  # Limit to first 5 results
                host_info = {
                    'ip': result['ip_str'],
                    'port': result['port'],
                    'org': result.get('org', ''),
                    'location': f"{result.get('location', {}).get('city', '')}, {result.get('location', {}).get('country_name', '')}",
                    'product': result.get('product', ''),
                    'version': result.get('version', '')
                }
                shodan_data['hosts'].append(host_info)

            return shodan_data

        except Exception as e:
            self.logger.error(f"Shodan lookup failed: {e}")
            return {'error': str(e)}

    def get_greynoise_info(self, domain):
        """Get GreyNoise information"""
        api_key = self.get_api_key('GREYNOISE_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            # First resolve domain to IP via DoH (passive-friendly)
            ip_answers = self.doh_query(domain, record_type='A')
            ip = ip_answers[0] if ip_answers else None

            url = f"https://api.greynoise.io/v3/community/{ip}"
            headers = {'key': api_key}
            response = self.make_request(url, headers=headers)

            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"GreyNoise lookup failed: {e}")
            return {'error': str(e)}

    def get_abuse_info(self, domain):
        """Get abuse/threat information"""
        # Placeholder for abuse information gathering
        return {'status': 'not_implemented'}

    def get_threat_intelligence(self, domain):
        """Get threat intelligence"""
        threat_info = {
            'alienvault_otx': self.get_alienvault_info(domain),
            'urlvoid_check': self.check_urlvoid(domain)
        }
        return threat_info

    def get_alienvault_info(self, domain):
        """Get AlienVault OTX information"""
        api_key = self.get_api_key('ALIENVAULT_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            headers = {'X-OTX-API-KEY': api_key}
            response = self.make_request(url, headers=headers)

            if response:
                data = response.json()
                return {
                    'pulse_count': len(data.get('pulse_info', {}).get('pulses', [])),
                    'malware_families': data.get('malware', {}).get('data', []),
                    'url_list': data.get('url_list', {}).get('url_list', [])[:10]  # Limit results
                }

        except Exception as e:
            self.logger.error(f"AlienVault OTX lookup failed: {e}")
            return {'error': str(e)}

    def check_urlvoid(self, domain):
        """Check URLVoid for reputation"""
        # Placeholder - URLVoid requires web scraping or paid API
        return {'status': 'not_implemented'}

    def get_certificate_info(self, domain):
        """Get SSL certificate information"""
        # This operation is active (opens a TCP connection). Ask for operator permission
        if not self.require_active_permission(reason=f"certificate retrieval for {domain}"):
            return {'error': 'Active checks disabled or not permitted by operator'}

        try:
            import socket
            import ssl

            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

            cert_info = {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'version': cert['version'],
                'serial_number': cert['serialNumber'],
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])]
            }

            return cert_info

        except Exception as e:
            self.logger.error(f"Certificate info lookup failed: {e}")
            return {'error': str(e)}

    def get_technology_stack(self, domain):
        """Get technology stack information"""
        builtwith_key = self.get_api_key('BUILTWITH_API_KEY')

        if builtwith_key:
            try:
                url = "https://api.builtwith.com/v20/api.json"
                params = {"KEY": builtwith_key, "LOOKUP": domain}
                response = self.make_request(url, params=params)
                if response:
                    return response.json()
            except Exception as e:
                self.logger.error(f"BuiltWith lookup failed: {e}")

        return {'status': 'no_api_key_or_failed'}

    def find_social_presence(self, domain):
        """Find social media presence"""
        # Extract company name from domain
        extracted = tldextract.extract(domain)
        company_name = extracted.domain

        social_platforms = {
            'twitter': f"https://twitter.com/{company_name}",
            'linkedin': f"https://linkedin.com/company/{company_name}",
            'facebook': f"https://facebook.com/{company_name}",
            'instagram': f"https://instagram.com/{company_name}",
            'youtube': f"https://youtube.com/c/{company_name}"
        }

        found_profiles = {}
        for platform, url in social_platforms.items():
            try:
                response = self.make_request(url, timeout=10)
                if response and response.status_code == 200:
                    found_profiles[platform] = url
            except Exception:
                continue

        return found_profiles

    def generate_report(self):
        """Generate comprehensive domain report"""
        if not self.results:
            return "No analysis results available"

        report = f"""
# Domain Analysis Report: {self.results['domain']}
Generated: {self.results['timestamp']}

## WHOIS Information
"""
        whois_info = self.results.get('whois_info', {})
        for key, value in whois_info.items():
            if value:
                report += f"- {key.replace('_', ' ').title()}: {value}\n"

        report += "\n## DNS Records\n"
        dns_records = self.results.get('dns_records', {})
        for record_type, records in dns_records.items():
            if records:
                report += f"- {record_type}: {', '.join(records)}\n"

        report += "\n## Subdomains Found\n"
        subdomains = self.results.get("subdomains", [])
        for subdomain in subdomains[:20]:  # Limit to first 20
            report += f"- {subdomain}\n"

        if len(subdomains) > 20:
            report += f"... and {len(subdomains) - 20} more\n"

        return report
