"""
IP and Network Intelligence Module
Comprehensive IP address and network analysis
"""

from datetime import datetime

from ipwhois import IPWhois

from utils.osint_utils import OSINTUtils


class IPIntelligence(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def analyze_ip(self, ip_address):
        """Comprehensive IP address analysis"""
        self.logger.info(f"Starting IP analysis for: {ip_address}")

        if not self.validate_input(ip_address, 'ip'):
            self.logger.error(f"Invalid IP format: {ip_address}")
            return {"status": "error", "error": f"Invalid IP format: {ip_address}"}

        try:
            self.results = {
                'ip': ip_address,
                'timestamp': datetime.now().isoformat(),
                'geolocation': self.get_geolocation(ip_address),
                'whois_info': self.get_ip_whois(ip_address),
                'reputation': self.check_ip_reputation(ip_address),
                'threat_intel': self.get_threat_intelligence(ip_address),
                'shodan_data': self.get_shodan_data(ip_address),
                'ports_services': self.scan_ports_services(ip_address),
                'reverse_dns': self.get_reverse_dns(ip_address),
                'asn_info': self.get_asn_info(ip_address),
                'abuse_contacts': self.get_abuse_contacts(ip_address)
            }

            return {"status": "success", "data": self.results}

        except Exception as e:
            self.logger.error(f"IP analysis failed: {e}")
            return {"status": "error", "error": str(e)}

    def get_geolocation(self, ip_address):
        """Get IP geolocation from multiple sources"""
        geo_data = {
            'ipinfo': self.get_ipinfo_data(ip_address),
            'ipapi': self.get_ipapi_data(ip_address),
            'ipstack': self.get_ipstack_data(ip_address),
            'abstractapi': self.get_abstractapi_geo(ip_address)
        }
        return geo_data

    def get_ipinfo_data(self, ip_address):
        """Get geolocation from IPInfo.io"""
        api_key = self.get_api_key('IPINFO_API_KEY')

        try:
            url = f"https://ipinfo.io/{ip_address}/json"
            params = {}
            if api_key:
                params['token'] = api_key

            response = self.make_request(url, params=params)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"IPInfo lookup failed: {e}")
            return {'error': str(e)}

    def get_ipapi_data(self, ip_address):
        """Get geolocation from IP-API"""
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = self.make_request(url)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"IP-API lookup failed: {e}")
            return {'error': str(e)}

    def get_ipstack_data(self, ip_address):
        """Get geolocation from IPStack"""
        api_key = self.get_api_key('IPSTACK_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = f"http://api.ipstack.com/{ip_address}"
            params = {'access_key': api_key}
            response = self.make_request(url, params=params)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"IPStack lookup failed: {e}")
            return {'error': str(e)}

    def get_abstractapi_geo(self, ip_address):
        """Get geolocation from AbstractAPI"""
        api_key = self.get_api_key('ABSTRACTAPI_IPGEOLOCATION')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = "https://ipgeolocation.abstractapi.com/v1/"
            params = {
                'api_key': api_key,
                'ip_address': ip_address
            }
            response = self.make_request(url, params=params)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"AbstractAPI geolocation failed: {e}")
            return {'error': str(e)}

    def get_ip_whois(self, ip_address):
        """Get IP WHOIS information"""
        # IPWhois performs network queries; request operator permission if active checks are disabled
        if not self.require_active_permission(reason=f"IP WHOIS lookup for {ip_address}"):
            return {'error': 'Active checks disabled or not permitted by operator'}

        try:
            obj = IPWhois(ip_address)
            results = obj.lookup_rdap()

            whois_data = {
                'asn': results.get('asn'),
                'asn_description': results.get('asn_description'),
                'asn_country_code': results.get('asn_country_code'),
                'network': results.get('network', {}),
                'entities': results.get('entities', [])
            }

            return whois_data

        except Exception as e:
            self.logger.error(f"IP WHOIS lookup failed: {e}")
            return {'error': str(e)}

    def check_ip_reputation(self, ip_address):
        """Check IP reputation across multiple sources"""
        reputation_data = {
            'abuseipdb': self.check_abuseipdb(ip_address),
            'greynoise': self.check_greynoise(ip_address),
            'virustotal': self.check_virustotal_ip(ip_address),
            'alienvault': self.check_alienvault_ip(ip_address)
        }
        return reputation_data

    def check_abuseipdb(self, ip_address):
        """Check AbuseIPDB"""
        api_key = self.get_api_key('ABUSEIPDB_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }

            response = self.make_request(url, headers=headers, params=params)
            if response:
                data = response.json()
                return {
                    'ip': data.get('data', {}).get('ipAddress'),
                    'abuse_confidence': data.get('data', {}).get('abuseConfidencePercentage'),
                    'country_code': data.get('data', {}).get('countryCode'),
                    'usage_type': data.get('data', {}).get('usageType'),
                    'isp': data.get('data', {}).get('isp'),
                    'domain': data.get('data', {}).get('domain'),
                    'is_whitelisted': data.get('data', {}).get('isWhitelisted'),
                    'total_reports': data.get('data', {}).get('totalReports'),
                    'num_distinct_users': data.get('data', {}).get('numDistinctUsers')
                }

        except Exception as e:
            self.logger.error(f"AbuseIPDB lookup failed: {e}")
            return {'error': str(e)}

    def check_greynoise(self, ip_address):
        """Check GreyNoise"""
        api_key = self.get_api_key('GREYNOISE_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = f"https://api.greynoise.io/v3/community/{ip_address}"
            headers = {'key': api_key}

            response = self.make_request(url, headers=headers)
            if response:
                return response.json()

        except Exception as e:
            self.logger.error(f"GreyNoise lookup failed: {e}")
            return {'error': str(e)}

    def check_virustotal_ip(self, ip_address):
        """Check VirusTotal for IP"""
        api_key = self.get_api_key('VIRUSTOTAL_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': api_key,
                'ip': ip_address
            }

            response = self.make_request(url, params=params)
            if response:
                data = response.json()
                return {
                    'detected_urls': data.get('detected_urls', [])[:10],  # Limit results
                    'detected_downloaded_samples': data.get('detected_downloaded_samples', [])[:10],
                    'detected_communicating_samples': data.get('detected_communicating_samples', [])[:10]
                }

        except Exception as e:
            self.logger.error(f"VirusTotal IP lookup failed: {e}")
            return {'error': str(e)}

    def check_alienvault_ip(self, ip_address):
        """Check AlienVault OTX for IP"""
        api_key = self.get_api_key('ALIENVAULT_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
            headers = {'X-OTX-API-KEY': api_key}

            response = self.make_request(url, headers=headers)
            if response:
                data = response.json()
                return {
                    'pulse_count': len(data.get('pulse_info', {}).get('pulses', [])),
                    'malware_samples': data.get('malware', {}).get('data', [])[:10],
                    'passive_dns': data.get('passive_dns', {}).get('passive_dns', [])[:10]
                }

        except Exception as e:
            self.logger.error(f"AlienVault IP lookup failed: {e}")
            return {'error': str(e)}

    def get_threat_intelligence(self, ip_address):
        """Get comprehensive threat intelligence"""
        threat_data = {
            'honeypot_check': self.check_honeypot(ip_address),
            'botscout_check': self.check_botscout(ip_address),
            'fraudguard_check': self.check_fraudguard(ip_address)
        }
        return threat_data

    def check_honeypot(self, ip_address):
        """Check if IP is a honeypot"""
        api_key = self.get_api_key('HONEYPOT_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        # Placeholder for honeypot checking service
        return {'status': 'not_implemented'}

    def check_botscout(self, ip_address):
        """Check BotScout"""
        api_key = self.get_api_key('BOTSCOUT_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            url = "http://botscout.com/test/"
            params = {
                'ip': ip_address,
                'key': api_key
            }

            response = self.make_request(url, params=params)
            if response:
                result = response.text.strip()
                return {
                    'is_bot': result.startswith('Y'),
                    'result': result
                }

        except Exception as e:
            self.logger.error(f"BotScout lookup failed: {e}")
            return {'error': str(e)}

    def check_fraudguard(self, ip_address):
        """Check FraudGuard"""
        account = self.get_api_key('FRAUDGUARD_ACCOUNT')
        password = self.get_api_key('FRAUDGUARD_PASSWORD')

        if not account or not password:
            return {'error': 'No API credentials'}

        # Placeholder for FraudGuard implementation
        return {'status': 'not_implemented'}

    def get_shodan_data(self, ip_address):
        """Get Shodan data for IP"""
        api_key = self.get_api_key('SHODAN_API_KEY')
        if not api_key:
            return {'error': 'No API key'}

        try:
            import shodan
            api = shodan.Shodan(api_key)
            host = api.host(ip_address)

            shodan_data = {
                'ip': host['ip_str'],
                'organization': host.get('org', ''),
                'operating_system': host.get('os'),
                'country_name': host.get('country_name', ''),
                'city': host.get('city', ''),
                'isp': host.get('isp', ''),
                'ports': host.get('ports', []),
                'hostnames': host.get('hostnames', []),
                'domains': host.get('domains', []),
                'tags': host.get('tags', []),
                'vulns': list(host.get('vulns', [])),
                'services': []
            }

            # Get service information
            for service in host.get('data', [])[:5]:  # Limit to first 5 services
                service_info = {
                    'port': service['port'],
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'banner': service.get('data', '')[:200]  # Truncate banner
                }
                shodan_data['services'].append(service_info)

            return shodan_data

        except Exception as e:
            self.logger.error(f"Shodan lookup failed: {e}")
            return {'error': str(e)}

    def scan_ports_services(self, ip_address):
        """Basic port scanning (passive only - using Shodan data)"""
        # For passive reconnaissance, we rely on Shodan data
        # Active port scanning would not be passive
        shodan_data = self.get_shodan_data(ip_address)

        if 'ports' in shodan_data:
            return {
                'method': 'passive_shodan',
                'open_ports': shodan_data['ports'],
                'services': shodan_data.get('services', [])
            }
        else:
            return {'error': 'No passive port data available'}

    def get_reverse_dns(self, ip_address):
        """Get reverse DNS"""
        try:
            # Use DoH-based reverse DNS to avoid system resolver leakage
            hostname = self.reverse_dns(ip_address)
            if hostname:
                return {'hostname': hostname}
            else:
                return {'error': 'PTR not found'}
        except Exception as e:
            self.logger.error(f"Reverse DNS lookup failed: {e}")
            return {'error': str(e)}

    def get_asn_info(self, ip_address):
        """Get ASN information"""
        if not self.require_active_permission(reason=f"ASN lookup for {ip_address}"):
            return {'error': 'Active checks disabled or not permitted by operator'}

        try:
            obj = IPWhois(ip_address)
            results = obj.lookup_rdap()

            asn_info = {
                'asn': results.get('asn'),
                'asn_description': results.get('asn_description'),
                'asn_country_code': results.get('asn_country_code'),
                'asn_registry': results.get('asn_registry')
            }

            return asn_info

        except Exception as e:
            self.logger.error(f"ASN lookup failed: {e}")
            return {'error': str(e)}

    def get_abuse_contacts(self, ip_address):
        """Get abuse contact information"""
        if not self.require_active_permission(reason=f"abuse contact lookup for {ip_address}"):
            return {'error': 'Active checks disabled or not permitted by operator'}

        try:
            obj = IPWhois(ip_address)
            results = obj.lookup_rdap()

            abuse_contacts = []
            for entity in results.get('entities', []):
                if 'abuse' in entity.lower() or 'security' in entity.lower():
                    abuse_contacts.append(entity)

            return {'abuse_contacts': abuse_contacts}

        except Exception as e:
            self.logger.error(f"Abuse contact lookup failed: {e}")
            return {'error': str(e)}

    def generate_report(self):
        """Generate comprehensive IP intelligence report"""
        if not self.results:
            return "No analysis results available"

        report = f"""
# IP Intelligence Report: {self.results['ip']}
Generated: {self.results['timestamp']}

## Geolocation Information
"""

        # Add geolocation data
        geo = self.results.get('geolocation', {})
        ipapi_data = geo.get('ipapi', {})

        if 'country' in ipapi_data:
            report += f"Country: {ipapi_data.get('country')} ({ipapi_data.get('countryCode')})\n"
            report += f"Region: {ipapi_data.get('regionName')}\n"
            report += f"City: {ipapi_data.get('city')}\n"
            report += f"ISP: {ipapi_data.get('isp')}\n"
            report += f"Organization: {ipapi_data.get('org')}\n"

        # Add reputation information
        reputation = self.results.get('reputation', {})
        abuseipdb = reputation.get('abuseipdb', {})

        report += "\n## Reputation Analysis\n"
        if 'abuse_confidence' in abuseipdb:
            confidence = abuseipdb['abuse_confidence']
            if confidence > 75:
                report += f"🚨 HIGH RISK: Abuse confidence {confidence}%\n"
            elif confidence > 25:
                report += f"⚠️  MEDIUM RISK: Abuse confidence {confidence}%\n"
            else:
                report += f"✅ LOW RISK: Abuse confidence {confidence}%\n"

            report += f"Total Reports: {abuseipdb.get('total_reports', 0)}\n"
            report += f"Usage Type: {abuseipdb.get('usage_type')}\n"

        # Add Shodan data
        shodan_data = self.results.get('shodan_data', {})
        if 'ports' in shodan_data:
            report += "\n## Open Ports & Services\n"
            for port in shodan_data['ports'][:10]:  # Limit to first 10
                report += f"- Port {port}\n"

            if shodan_data.get('vulns'):
                report += "\n## Known Vulnerabilities\n"
                for vuln in shodan_data['vulns'][:5]:  # Limit to first 5
                    report += f"- {vuln}\n"

        return report
