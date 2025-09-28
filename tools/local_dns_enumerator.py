"""
Local DNS Enumeration Module

This module provides DNS enumeration capabilities using local DNS resolution:
- DNS record enumeration
- Reverse DNS lookup
- Zone transfer attempts
- DNSSEC validation
- Local DNS cache analysis
"""

import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.exception
import ipaddress
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.osint_utils import OSINTUtils


class LocalDNSEnumerator(OSINTUtils):
    """Local DNS enumeration without external API dependencies"""

    def __init__(self):
        super().__init__()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

        # Common DNS record types to check
        self.record_types = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'SRV',
            'PTR', 'HINFO', 'MINFO', 'RP', 'AFSDB', 'X25', 'ISDN',
            'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS',
            'AAAA', 'LOC', 'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA',
            'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'SINK', 'OPT',
            'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC',
            'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA',
            'SMIMEA', 'HIP', 'NINFO', 'RKEY', 'TALINK', 'CDS',
            'CDNSKEY', 'OPENPGPKEY', 'CSYNC', 'ZONEMD', 'SVCB', 'HTTPS'
        ]

    def enumerate_domain(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS enumeration for a domain"""
        results = {
            "domain": domain,
            "records": {},
            "nameservers": [],
            "mx_records": [],
            "txt_records": [],
            "subdomains": [],
            "errors": []
        }

        # Get basic DNS records
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT']:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results["records"][record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                results["records"][record_type] = []
            except Exception as e:
                results["errors"].append(f"{record_type}: {str(e)}")

        # Extract specific record types
        results["nameservers"] = results["records"].get("NS", [])
        results["mx_records"] = results["records"].get("MX", [])
        results["txt_records"] = results["records"].get("TXT", [])

        # Attempt zone transfer
        results["zone_transfer"] = self._attempt_zone_transfer(domain)

        # Check for common subdomains
        results["subdomains"] = self._check_common_subdomains(domain)

        # DNSSEC check
        results["dnssec"] = self._check_dnssec(domain)

        return results

    def _attempt_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt zone transfer from authoritative nameservers"""
        results = {"successful": False, "records": []}

        try:
            # Get nameservers
            ns_answers = self.resolver.resolve(domain, 'NS')
            nameservers = [str(ns) for ns in ns_answers]

            for ns in nameservers:
                try:
                    # Try zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    results["successful"] = True
                    results["source"] = ns

                    # Extract all records
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            record_data = {
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "ttl": rdataset.ttl,
                                "data": [str(rdata) for rdata in rdataset]
                            }
                            results["records"].append(record_data)

                    break  # Stop after first successful transfer

                except Exception:
                    continue  # Try next nameserver

        except Exception as e:
            results["error"] = str(e)

        return results

    def _check_common_subdomains(self, domain: str, max_workers: int = 10) -> List[str]:
        """Check for common subdomains using DNS resolution"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'app', 'mobile', 'm', 'webmail', 'remote',
            'vpn', 'git', 'svn', 'ci', 'cdn', 'static', 'assets', 'img', 'images',
            'video', 'videos', 'download', 'downloads', 'files', 'upload',
            'portal', 'login', 'auth', 'secure', 'ssl', 'beta', 'demo'
        ]

        found_subdomains = []

        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                self.resolver.resolve(full_domain, 'A')
                return full_domain
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)

        return found_subdomains

    def _check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC configuration"""
        results = {"enabled": False, "keys": [], "signatures": []}

        try:
            # Check for DNSKEY records
            dnskey_answers = self.resolver.resolve(domain, 'DNSKEY')
            results["enabled"] = True
            results["keys"] = [str(key) for key in dnskey_answers]

            # Check for RRSIG records
            rrsig_answers = self.resolver.resolve(domain, 'RRSIG')
            results["signatures"] = [str(sig) for sig in rrsig_answers]

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # DNSSEC not configured
        except Exception as e:
            results["error"] = str(e)

        return results

    def reverse_lookup(self, ip_address: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup"""
        results = {"ip": ip_address, "ptr_records": []}

        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)

            # Create reverse name
            reverse_name = dns.reversename.from_address(ip_address)

            # Perform PTR lookup
            ptr_answers = self.resolver.resolve(reverse_name, 'PTR')
            results["ptr_records"] = [str(ptr) for ptr in ptr_answers]

        except ValueError:
            results["error"] = "Invalid IP address"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            results["ptr_records"] = []
        except Exception as e:
            results["error"] = str(e)

        return results

    def bulk_reverse_lookup(self, ip_list: List[str], max_workers: int = 20) -> List[Dict[str, Any]]:
        """Perform reverse DNS lookup on multiple IPs"""
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.reverse_lookup, ip) for ip in ip_list]
            for future in as_completed(futures):
                results.append(future.result())

        return results

    def check_dns_health(self, domain: str) -> Dict[str, Any]:
        """Check overall DNS health and configuration"""
        results = {
            "domain": domain,
            "checks": {},
            "score": 0,
            "issues": []
        }

        # Check for basic records
        basic_records = ['A', 'MX', 'NS']
        for record_type in basic_records:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results["checks"][f"{record_type}_record"] = len(answers) > 0
                if len(answers) > 0:
                    results["score"] += 1
            except Exception:
                results["checks"][f"{record_type}_record"] = False
                results["issues"].append(f"Missing {record_type} record")

        # Check for SPF
        try:
            txt_answers = self.resolver.resolve(domain, 'TXT')
            has_spf = any('v=spf1' in str(txt) for txt in txt_answers)
            results["checks"]["spf_record"] = has_spf
            if has_spf:
                results["score"] += 1
            else:
                results["issues"].append("Missing SPF record")
        except Exception:
            results["checks"]["spf_record"] = False
            results["issues"].append("Missing SPF record")

        # Check for DMARC
        try:
            dmarc_answers = self.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            has_dmarc = any('v=DMARC1' in str(dmarc) for dmarc in dmarc_answers)
            results["checks"]["dmarc_record"] = has_dmarc
            if has_dmarc:
                results["score"] += 1
            else:
                results["issues"].append("Missing DMARC record")
        except Exception:
            results["checks"]["dmarc_record"] = False
            results["issues"].append("Missing DMARC record")

        # Calculate percentage score
        results["score_percentage"] = (results["score"] / 5) * 100

        return results

    def enumerate_ip_range(self, ip_range: str) -> List[Dict[str, Any]]:
        """Enumerate PTR records for an IP range (be careful with this!)"""
        results = []

        try:
            network = ipaddress.ip_network(ip_range, strict=False)

            # Limit to reasonable sizes to avoid abuse
            if network.num_addresses > 1000:
                return [{"error": "IP range too large (>1000 addresses)"}]

            ip_list = [str(ip) for ip in network.hosts()]

            # Sample a subset for performance
            if len(ip_list) > 100:
                import random
                ip_list = random.sample(ip_list, 100)

            results = self.bulk_reverse_lookup(ip_list)

        except Exception as e:
            results = [{"error": str(e)}]

        return results