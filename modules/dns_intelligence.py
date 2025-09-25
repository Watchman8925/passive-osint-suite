"""
DNS Intelligence and Domain Analysis Module
Provides comprehensive DNS reconnaissance using open source tools
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import tempfile
import shutil
import re
import socket

logger = logging.getLogger(__name__)

class DNSIntelligenceEngine:
    """DNS intelligence engine using open source tools"""

    def __init__(self):
        self.tools = {
            'dnsrecon': self._check_tool('dnsrecon'),
            'dig': self._check_tool('dig'),
            'nslookup': self._check_tool('nslookup'),
            'host': self._check_tool('host'),
            'amass': self._check_tool('amass'),
            'shuffledns': self._check_tool('shuffledns'),
            'puredns': self._check_tool('puredns'),
            'alterx': self._check_tool('alterx'),
            'gotator': self._check_tool('gotator'),
            'dnsgen': self._check_tool('dnsgen'),
            'dnstwist': self._check_tool('dnstwist')
        }

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            subprocess.run([tool_name, '--help' if tool_name not in ['dig', 'nslookup', 'host'] else '-h'],
                         capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def dns_reconnaissance(self, domain: str, recon_type: str = 'standard') -> Dict[str, Any]:
        """
        Perform DNS reconnaissance using dnsrecon

        Args:
            domain: Target domain
            recon_type: Type of reconnaissance ('standard', 'brute', 'axfr', 'all')

        Returns:
            Dictionary containing DNS reconnaissance results
        """
        if not self.tools['dnsrecon']:
            return {"error": "dnsrecon not available"}

        try:
            cmd = ['dnsrecon', '-d', domain, '--json']

            if recon_type == 'brute':
                cmd.extend(['-D', '/usr/share/dnsrecon/namelist.txt', '-t', 'brt'])
            elif recon_type == 'axfr':
                cmd.extend(['-t', 'axfr'])
            elif recon_type == 'all':
                cmd.extend(['-t', 'std,brt,axfr,srv,zonewalk'])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            records = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            record = json.loads(line)
                            records.append(record)
                        except json.JSONDecodeError:
                            continue

            # Categorize records
            categorized = self._categorize_dns_records(records)

            return {
                "success": True,
                "domain": domain,
                "recon_type": recon_type,
                "total_records": len(records),
                "records": records,
                "categorized": categorized
            }

        except subprocess.TimeoutExpired:
            return {"error": "DNS reconnaissance timeout"}

    def _categorize_dns_records(self, records: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Categorize DNS records by type

        Args:
            records: List of DNS records

        Returns:
            Dictionary with categorized records
        """
        categories = {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "TXT": [],
            "NS": [],
            "SOA": [],
            "SRV": [],
            "PTR": [],
            "other": []
        }

        for record in records:
            record_type = record.get('type', 'other')
            if record_type in categories:
                categories[record_type].append(record)
            else:
                categories["other"].append(record)

        return categories

    def passive_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """
        Perform passive DNS enumeration using available tools

        Args:
            domain: Target domain

        Returns:
            Dictionary containing passive DNS results
        """
        results = {
            "domain": domain,
            "passive_sources": {}
        }

        # Try dnsrecon passive enumeration
        if self.tools['dnsrecon']:
            try:
                result = subprocess.run(
                    ['dnsrecon', '-d', domain, '-t', 'std', '--json'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                passive_records = []
                if result.returncode == 0 and result.stdout:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            try:
                                record = json.loads(line)
                                passive_records.append(record)
                            except json.JSONDecodeError:
                                continue

                results["passive_sources"]["dnsrecon"] = {
                    "records": passive_records,
                    "count": len(passive_records)
                }

            except subprocess.TimeoutExpired:
                results["passive_sources"]["dnsrecon"] = {"error": "timeout"}

        # Try dig for basic enumeration
        if self.tools['dig']:
            try:
                result = subprocess.run(
                    ['dig', domain, 'ANY', '+noall', '+answer'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    results["passive_sources"]["dig"] = {
                        "output": result.stdout.strip(),
                        "success": True
                    }

            except subprocess.TimeoutExpired:
                results["passive_sources"]["dig"] = {"error": "timeout"}

        return results

    def subdomain_enumeration(self, domain: str, wordlist_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform subdomain enumeration

        Args:
            domain: Target domain
            wordlist_path: Path to wordlist file (optional)

        Returns:
            Dictionary containing subdomain enumeration results
        """
        results = {
            "domain": domain,
            "subdomains": [],
            "sources": {}
        }

        # Use dnsrecon for subdomain brute force if wordlist available
        if self.tools['dnsrecon'] and wordlist_path and os.path.exists(wordlist_path):
            try:
                result = subprocess.run(
                    ['dnsrecon', '-d', domain, '-D', wordlist_path, '-t', 'brt', '--json'],
                    capture_output=True,
                    text=True,
                    timeout=600
                )

                subdomains = []
                if result.returncode == 0 and result.stdout:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            try:
                                record = json.loads(line)
                                if record.get('type') == 'A' and 'name' in record:
                                    subdomains.append(record['name'])
                            except json.JSONDecodeError:
                                continue

                results["sources"]["dnsrecon_brute"] = {
                    "subdomains": list(set(subdomains)),
                    "count": len(set(subdomains))
                }
                results["subdomains"].extend(subdomains)

            except subprocess.TimeoutExpired:
                results["sources"]["dnsrecon_brute"] = {"error": "timeout"}

        # Try host command for basic enumeration
        if self.tools['host']:
            try:
                result = subprocess.run(
                    ['host', '-l', domain],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.returncode == 0 and result.stdout:
                    # Parse host output for subdomains
                    lines = result.stdout.split('\n')
                    host_subdomains = []
                    for line in lines:
                        if 'domain name pointer' in line:
                            parts = line.split()
                            if len(parts) > 0:
                                subdomain = parts[0].rstrip('.')
                                if subdomain.endswith(f'.{domain}'):
                                    host_subdomains.append(subdomain)

                    results["sources"]["host"] = {
                        "subdomains": host_subdomains,
                        "count": len(host_subdomains)
                    }
                    results["subdomains"].extend(host_subdomains)

            except subprocess.TimeoutExpired:
                results["sources"]["host"] = {"error": "timeout"}

        # Remove duplicates
        results["subdomains"] = list(set(results["subdomains"]))
        results["total_subdomains"] = len(results["subdomains"])

        return results

    def domain_permutation_generation(self, domain: str) -> Dict[str, Any]:
        """
        Generate domain permutations for typo-squatting detection

        Args:
            domain: Base domain

        Returns:
            Dictionary containing generated permutations
        """
        permutations = []

        # Basic permutation techniques
        base_domain = domain.replace('www.', '').split('.')[0]
        tld = '.'.join(domain.split('.')[1:]) if '.' in domain else 'com'

        # Character substitution
        substitutions = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7']
        }

        # Generate substitutions
        for char, subs in substitutions.items():
            if char in base_domain:
                for sub in subs:
                    perm = base_domain.replace(char, sub)
                    permutations.append(f"{perm}.{tld}")

        # Missing dot
        if len(base_domain) > 3:
            permutations.append(f"{base_domain}{tld}")

        # Character omission
        for i in range(len(base_domain)):
            perm = base_domain[:i] + base_domain[i+1:]
            if len(perm) > 2:
                permutations.append(f"{perm}.{tld}")

        # Character repetition
        for i in range(len(base_domain)):
            perm = base_domain[:i] + base_domain[i] + base_domain[i:]
            permutations.append(f"{perm}.{tld}")

        # Remove duplicates and filter
        unique_perms = list(set(permutations))
        valid_perms = [p for p in unique_perms if len(p) > 3 and p != domain]

        return {
            "success": True,
            "base_domain": domain,
            "total_permutations": len(valid_perms),
            "permutations": valid_perms[:200],  # Limit for performance
            "techniques": ["substitution", "omission", "repetition", "missing_dot"]
        }

    def dns_zone_transfer_check(self, domain: str) -> Dict[str, Any]:
        """
        Check for DNS zone transfer vulnerability

        Args:
            domain: Target domain

        Returns:
            Dictionary containing zone transfer results
        """
        results = {
            "domain": domain,
            "zone_transfer_possible": False,
            "nameservers": [],
            "vulnerable_servers": []
        }

        # Get nameservers first
        try:
            ns_result = subprocess.run(
                ['dig', 'NS', domain, '+short'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if ns_result.returncode == 0 and ns_result.stdout:
                nameservers = [ns.strip('.') for ns in ns_result.stdout.strip().split('\n') if ns.strip()]
                results["nameservers"] = nameservers

                # Try zone transfer on each nameserver
                for ns in nameservers:
                    try:
                        axfr_result = subprocess.run(
                            ['dig', '@' + ns, 'AXFR', domain],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )

                        if axfr_result.returncode == 0 and 'Transfer failed' not in axfr_result.stdout:
                            # Check if we got actual zone data
                            if 'SOA' in axfr_result.stdout and len(axfr_result.stdout) > 100:
                                results["zone_transfer_possible"] = True
                                results["vulnerable_servers"].append({
                                    "server": ns,
                                    "data": axfr_result.stdout[:2000]  # Limit output
                                })

                    except subprocess.TimeoutExpired:
                        continue

        except subprocess.TimeoutExpired:
            results["error"] = "Nameserver enumeration timeout"

        return results

    def reverse_dns_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup

        Args:
            ip_address: IP address to lookup

        Returns:
            Dictionary containing reverse DNS results
        """
        try:
            hostname = socket.gethostbyaddr(ip_address)
            return {
                "success": True,
                "ip_address": ip_address,
                "hostname": hostname[0],
                "aliases": hostname[1],
                "addresses": hostname[2]
            }
        except (socket.herror, socket.gaierror) as e:
            return {
                "success": False,
                "ip_address": ip_address,
                "error": str(e)
            }

    def comprehensive_dns_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive DNS analysis on a domain

        Args:
            domain: Target domain

        Returns:
            Dictionary containing all DNS analysis results
        """
        analysis = {
            "domain": domain,
            "timestamp": None,  # Would be set by caller
            "analyses": {}
        }

        # DNS reconnaissance
        analysis["analyses"]["dns_recon"] = self.dns_reconnaissance(domain, 'standard')

        # Passive DNS enumeration
        analysis["analyses"]["passive_dns"] = self.passive_dns_enumeration(domain)

        # Subdomain enumeration (basic)
        analysis["analyses"]["subdomains"] = self.subdomain_enumeration(domain)

        # Domain permutations
        analysis["analyses"]["permutations"] = self.domain_permutation_generation(domain)

        # Zone transfer check
        analysis["analyses"]["zone_transfer"] = self.dns_zone_transfer_check(domain)

        return analysis