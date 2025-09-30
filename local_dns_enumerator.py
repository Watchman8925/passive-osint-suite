#!/usr/bin/env python3
"""
Local DNS Enumerator Module
DNS enumeration and analysis for local networks.
"""

import logging
import socket
import subprocess
import ipaddress
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.query
    import dns.zone

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logger.warning("dnspython not available - advanced DNS features disabled")


class LocalDNSEnumerator:
    """Advanced local DNS enumerator"""

    def __init__(self):
        self.enabled = True
        self.timeout = 5
        self.max_workers = 10

        # Common DNS record types to check
        self.record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME", "PTR"]

        # Common subdomain prefixes to try
        self.common_prefixes = [
            "www",
            "mail",
            "ftp",
            "admin",
            "test",
            "dev",
            "staging",
            "api",
            "vpn",
            "remote",
            "portal",
            "webmail",
            "smtp",
            "pop",
            "imap",
            "ns1",
            "ns2",
            "dns1",
            "dns2",
            "gw",
            "gateway",
            "router",
            "dhcp",
        ]

        logger.info("LocalDNSEnumerator initialized with DNS enumeration capabilities")

    def enumerate_domain(self, domain: str) -> Dict[str, Any]:
        """Enumerate DNS records for domain"""
        try:
            results: Dict[str, Any] = {
                "domain": domain,
                "records": {},
                "subdomains": [],
                "enumerated": True,
                "timestamp": time.time(),
            }

            # Enumerate different record types
            for record_type in self.record_types:
                records = self._query_dns_records(domain, record_type)
                if records:
                    results["records"][record_type] = records

            # Try subdomain enumeration
            subdomains = self._enumerate_subdomains(domain)
            results["subdomains"] = subdomains

            # Analyze results
            results["analysis"] = self._analyze_dns_results(results)

            return results

        except Exception as e:
            logger.error(f"Failed to enumerate domain {domain}: {e}")
            return {
                "domain": domain,
                "records": {},
                "subdomains": [],
                "enumerated": False,
                "error": str(e),
            }

    def _query_dns_records(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """Query specific DNS record type"""
        records = []

        try:
            if HAS_DNSPYTHON:
                resolver = dns.resolver.Resolver()  # type: ignore
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout

                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    record_data = {
                        "type": record_type,
                        "value": str(answer),
                        "ttl": getattr(answer, "ttl", None),
                    }
                    records.append(record_data)
            else:
                # Fallback using system dig if available
                try:
                    result = subprocess.run(
                        ["dig", domain, record_type, "+short"],
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        for line in result.stdout.strip().split("\n"):
                            if line.strip():
                                records.append(
                                    {
                                        "type": record_type,
                                        "value": line.strip(),
                                        "ttl": None,
                                    }
                                )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

        except Exception as e:
            logger.debug(f"Failed to query {record_type} records for {domain}: {e}")

        return records

    def _enumerate_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Enumerate potential subdomains"""
        subdomains = []

        def check_subdomain(prefix: str) -> Optional[Dict[str, Any]]:
            subdomain = f"{prefix}.{domain}"
            try:
                # Quick resolution check
                socket.gethostbyname(subdomain)
                return {
                    "subdomain": subdomain,
                    "resolved": True,
                    "ip": socket.gethostbyname(subdomain),
                }
            except socket.gaierror:
                return None

        # Check common prefixes
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(check_subdomain, prefix)
                for prefix in self.common_prefixes
            ]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)

        return subdomains

    def _analyze_dns_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze DNS enumeration results"""
        analysis: Dict[str, Any] = {
            "record_count": sum(
                len(records) for records in results.get("records", {}).values()
            ),
            "subdomain_count": len(results.get("subdomains", [])),
            "has_mx": bool(results.get("records", {}).get("MX")),
            "has_ns": bool(results.get("records", {}).get("NS")),
            "has_aaaa": bool(results.get("records", {}).get("AAAA")),
            "security_indicators": [],
        }

        # Check for security indicators
        records = results.get("records", {})

        # Check for SPF records
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf" in str(record.get("value", "")) for record in txt_records)
        if has_spf:
            analysis["security_indicators"].append("SPF configured")
        else:
            analysis["security_indicators"].append("No SPF record")

        # Check for DMARC
        dmarc_records = self._query_dns_records(f"_dmarc.{results['domain']}", "TXT")
        if dmarc_records:
            analysis["security_indicators"].append("DMARC configured")
        else:
            analysis["security_indicators"].append("No DMARC record")

        # Check for DKIM selector
        dkim_records = self._query_dns_records(
            f"default._domainkey.{results['domain']}", "TXT"
        )
        if dkim_records:
            analysis["security_indicators"].append("DKIM configured")
        else:
            analysis["security_indicators"].append("No DKIM record")

        # Analyze IP ranges
        ips = []
        for record_type in ["A", "AAAA"]:
            for record in records.get(record_type, []):
                if record_type == "A":
                    ips.append(record.get("value", ""))

        if ips:
            analysis["ip_analysis"] = self._analyze_ip_ranges(ips)

        return analysis

    def _analyze_ip_ranges(self, ips: List[str]) -> Dict[str, Any]:
        """Analyze IP address ranges"""
        try:
            networks = set()
            for ip in ips:
                try:
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    networks.add(str(network))
                except ValueError:
                    continue

            return {
                "unique_networks": len(networks),
                "networks": list(networks),
                "geographic_distribution": "analysis_not_implemented",  # Could be enhanced
            }
        except Exception as e:
            return {"error": str(e)}

    def scan_network(self, network: str) -> Dict[str, Any]:
        """Scan network for DNS servers and analyze DNS infrastructure"""
        try:
            results: Dict[str, Any] = {
                "network": network,
                "dns_servers": [],
                "scanned": True,
                "timestamp": time.time(),
            }

            # Parse network
            try:
                net = ipaddress.ip_network(network, strict=False)
            except ValueError:
                return {
                    "network": network,
                    "dns_servers": [],
                    "scanned": False,
                    "error": "Invalid network",
                }

            # Common DNS server ports: 53, 5353 (Standard DNS and mDNS)
            # Scan for DNS servers (basic implementation)
            potential_dns_servers: List[Dict[str, Any]] = []

            # Check network gateway (common DNS server location)
            if net.num_addresses > 1:
                gateway_ip = str(net.network_address + 1)  # Usually .1
                if self._test_dns_server(gateway_ip):
                    potential_dns_servers.append(
                        {"ip": gateway_ip, "type": "gateway", "responsive": True}
                    )

            # Check other common DNS server locations
            for offset in [1, 2, 10, 100]:
                if offset < net.num_addresses:
                    test_ip = str(net.network_address + offset)
                    if self._test_dns_server(test_ip):
                        potential_dns_servers.append(
                            {
                                "ip": test_ip,
                                "type": "common_location",
                                "responsive": True,
                            }
                        )

            results["dns_servers"] = potential_dns_servers
            results["analysis"] = {
                "server_count": len(potential_dns_servers),
                "network_size": net.num_addresses,
                "scan_coverage": "partial",  # Only checking common locations
            }

            return results

        except Exception as e:
            logger.error(f"Failed to scan network {network}: {e}")
            return {
                "network": network,
                "dns_servers": [],
                "scanned": False,
                "error": str(e),
            }

    def _test_dns_server(self, ip: str, timeout: float = 2.0) -> bool:
        """Test if an IP is running a DNS server"""
        try:
            if HAS_DNSPYTHON:
                # Try to resolve a common domain
                socket.setdefaulttimeout(timeout)
                resolver = dns.resolver.Resolver()  # type: ignore
                resolver.nameservers = [ip]
                resolver.timeout = timeout
                resolver.lifetime = timeout

                # Test with a simple query
                answers = resolver.resolve("google.com", "A")
                return len(answers) > 0
            else:
                return False

        except Exception:
            return False

    def enumerate_zone(self, domain: str) -> Dict[str, Any]:
        """Attempt zone transfer enumeration"""
        try:
            results: Dict[str, Any] = {
                "domain": domain,
                "zone_transfer_successful": False,
                "records": [],
                "vulnerable_nameservers": [],
            }

            if not HAS_DNSPYTHON:
                results["error"] = "dnspython not available for zone transfer"
                return results

            # Get nameservers
            ns_records = self._query_dns_records(domain, "NS")
            nameservers = [record["value"].rstrip(".") for record in ns_records]

            for ns in nameservers:
                try:
                    # Try zone transfer
                    import dns.zone
                    import dns.query

                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    if zone:
                        results["zone_transfer_successful"] = True
                        results["vulnerable_nameservers"].append(ns)

                        # Extract records
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                results["records"].append(
                                    {
                                        "name": str(name),
                                        "type": rdataset.rdtype,
                                        "data": [str(rdata) for rdata in rdataset],
                                    }
                                )

                except Exception as e:
                    logger.debug(f"Zone transfer failed for {ns}: {e}")

            return results

        except Exception as e:
            logger.error(f"Failed to enumerate zone for {domain}: {e}")
            return {
                "domain": domain,
                "zone_transfer_successful": False,
                "error": str(e),
            }
