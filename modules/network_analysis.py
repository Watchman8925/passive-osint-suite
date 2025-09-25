"""
Network Analysis and Traffic Intelligence Module
Provides passive network analysis using Wireshark/tshark and other tools
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

logger = logging.getLogger(__name__)

class NetworkAnalysisEngine:
    """Network analysis engine using open source tools"""

    def __init__(self):
        self.tools = {
            'tshark': self._check_tool('tshark'),
            'tcpdump': self._check_tool('tcpdump'),
            'zeek': self._check_tool('zeek'),
            'p0f': self._check_tool('p0f')
        }

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            subprocess.run([tool_name, '--help' if tool_name != 'zeek' else '--version'],
                         capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def analyze_pcap_file(self, pcap_path: str, analysis_type: str = 'summary') -> Dict[str, Any]:
        """
        Analyze a PCAP file using tshark

        Args:
            pcap_path: Path to the PCAP file
            analysis_type: Type of analysis ('summary', 'conversations', 'endpoints', 'protocols')

        Returns:
            Dictionary containing analysis results
        """
        if not self.tools['tshark']:
            return {"error": "tshark not available"}

        if not os.path.exists(pcap_path):
            return {"error": f"PCAP file not found: {pcap_path}"}

        results = {
            "pcap_file": pcap_path,
            "analysis_type": analysis_type,
            "results": {}
        }

        try:
            if analysis_type == 'summary':
                # Basic packet summary
                result = subprocess.run(
                    ['tshark', '-r', pcap_path, '-q', '-z', 'io,stat,0'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode == 0:
                    results["results"]["summary"] = self._parse_tshark_output(result.stdout)

            elif analysis_type == 'conversations':
                # Conversation statistics
                result = subprocess.run(
                    ['tshark', '-r', pcap_path, '-q', '-z', 'conv,tcp'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode == 0:
                    results["results"]["conversations"] = self._parse_conversations(result.stdout)

            elif analysis_type == 'endpoints':
                # Endpoint statistics
                result = subprocess.run(
                    ['tshark', '-r', pcap_path, '-q', '-z', 'endpoints,tcp'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode == 0:
                    results["results"]["endpoints"] = self._parse_endpoints(result.stdout)

            elif analysis_type == 'protocols':
                # Protocol hierarchy
                result = subprocess.run(
                    ['tshark', '-r', pcap_path, '-q', '-z', 'io,phs'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode == 0:
                    results["results"]["protocols"] = self._parse_protocols(result.stdout)

            # Extract basic packet info
            result = subprocess.run(
                ['tshark', '-r', pcap_path, '-T', 'json'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                try:
                    packets = json.loads(result.stdout)
                    results["results"]["packet_count"] = len(packets)
                    results["results"]["sample_packets"] = packets[:5] if packets else []
                except json.JSONDecodeError:
                    results["results"]["packet_count"] = 0

        except subprocess.TimeoutExpired:
            results["error"] = "PCAP analysis timeout"

        return results

    def _parse_tshark_output(self, output: str) -> Dict[str, Any]:
        """Parse tshark summary output"""
        lines = output.split('\n')
        summary = {}

        for line in lines:
            if '=' in line:
                key, value = line.split('=', 1)
                summary[key.strip()] = value.strip()

        return summary

    def _parse_conversations(self, output: str) -> List[Dict[str, Any]]:
        """Parse conversation statistics"""
        conversations = []
        lines = output.split('\n')

        # Skip header lines
        data_started = False
        for line in lines:
            if line.startswith('TCP Conversations'):
                data_started = True
                continue
            if data_started and line.strip() and not line.startswith('='):
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 6:
                    conv = {
                        "source": parts[0],
                        "destination": parts[2],
                        "packets": int(parts[4]) if parts[4].isdigit() else 0,
                        "bytes": int(parts[5]) if parts[5].isdigit() else 0
                    }
                    conversations.append(conv)

        return conversations

    def _parse_endpoints(self, output: str) -> List[Dict[str, Any]]:
        """Parse endpoint statistics"""
        endpoints = []
        lines = output.split('\n')

        data_started = False
        for line in lines:
            if line.startswith('TCP Endpoints'):
                data_started = True
                continue
            if data_started and line.strip() and not line.startswith('='):
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4:
                    endpoint = {
                        "address": parts[0],
                        "port": parts[1],
                        "packets": int(parts[2]) if parts[2].isdigit() else 0,
                        "bytes": int(parts[3]) if parts[3].isdigit() else 0
                    }
                    endpoints.append(endpoint)

        return endpoints

    def _parse_protocols(self, output: str) -> Dict[str, Any]:
        """Parse protocol hierarchy"""
        protocols = {}
        lines = output.split('\n')

        for line in lines:
            if '%' in line and 'Protocol' not in line:
                parts = line.split()
                if len(parts) >= 3:
                    protocol = ' '.join(parts[:-2])
                    percentage = parts[-2]
                    packets = parts[-1]

                    protocols[protocol] = {
                        "percentage": percentage,
                        "packets": int(packets) if packets.isdigit() else 0
                    }

        return protocols

    def extract_http_traffic(self, pcap_path: str) -> Dict[str, Any]:
        """
        Extract HTTP traffic from PCAP file

        Args:
            pcap_path: Path to the PCAP file

        Returns:
            Dictionary containing HTTP traffic analysis
        """
        if not self.tools['tshark']:
            return {"error": "tshark not available"}

        try:
            # Extract HTTP requests
            result = subprocess.run(
                ['tshark', '-r', pcap_path, '-Y', 'http.request',
                 '-T', 'fields', '-e', 'http.request.method',
                 '-e', 'http.request.uri', '-e', 'http.host'],
                capture_output=True,
                text=True,
                timeout=60
            )

            http_requests = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            request = {
                                "method": parts[0],
                                "uri": parts[1],
                                "host": parts[2]
                            }
                            http_requests.append(request)

            # Extract HTTP responses
            result = subprocess.run(
                ['tshark', '-r', pcap_path, '-Y', 'http.response',
                 '-T', 'fields', '-e', 'http.response.code',
                 '-e', 'http.response.phrase'],
                capture_output=True,
                text=True,
                timeout=60
            )

            http_responses = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            response = {
                                "code": parts[0],
                                "phrase": parts[1]
                            }
                            http_responses.append(response)

            return {
                "success": True,
                "pcap_file": pcap_path,
                "http_requests": http_requests,
                "http_responses": http_responses,
                "request_count": len(http_requests),
                "response_count": len(http_responses)
            }

        except subprocess.TimeoutExpired:
            return {"error": "HTTP traffic extraction timeout"}

    def analyze_dns_traffic(self, pcap_path: str) -> Dict[str, Any]:
        """
        Analyze DNS traffic from PCAP file

        Args:
            pcap_path: Path to the PCAP file

        Returns:
            Dictionary containing DNS traffic analysis
        """
        if not self.tools['tshark']:
            return {"error": "tshark not available"}

        try:
            # Extract DNS queries
            result = subprocess.run(
                ['tshark', '-r', pcap_path, '-Y', 'dns.flags.response == 0',
                 '-T', 'fields', '-e', 'dns.qry.name', '-e', 'dns.qry.type'],
                capture_output=True,
                text=True,
                timeout=60
            )

            dns_queries = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            query = {
                                "name": parts[0],
                                "type": parts[1]
                            }
                            dns_queries.append(query)

            # Extract DNS responses
            result = subprocess.run(
                ['tshark', '-r', pcap_path, '-Y', 'dns.flags.response == 1',
                 '-T', 'fields', '-e', 'dns.qry.name', '-e', 'dns.a'],
                capture_output=True,
                text=True,
                timeout=60
            )

            dns_responses = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            response = {
                                "name": parts[0],
                                "address": parts[1]
                            }
                            dns_responses.append(response)

            return {
                "success": True,
                "pcap_file": pcap_path,
                "dns_queries": dns_queries,
                "dns_responses": dns_responses,
                "query_count": len(dns_queries),
                "response_count": len(dns_responses)
            }

        except subprocess.TimeoutExpired:
            return {"error": "DNS traffic analysis timeout"}

    def detect_anomalies(self, pcap_path: str) -> Dict[str, Any]:
        """
        Detect network anomalies in PCAP file

        Args:
            pcap_path: Path to the PCAP file

        Returns:
            Dictionary containing anomaly detection results
        """
        analysis = self.analyze_pcap_file(pcap_path, 'summary')
        if "error" in analysis:
            return analysis

        anomalies = {
            "pcap_file": pcap_path,
            "anomalies": [],
            "risk_score": 0
        }

        # Check for suspicious patterns
        if "results" in analysis and "conversations" in analysis["results"]:
            conversations = analysis["results"]["conversations"]

            # Check for high-volume connections
            for conv in conversations:
                if conv.get("packets", 0) > 10000:  # Arbitrary threshold
                    anomalies["anomalies"].append({
                        "type": "high_volume_connection",
                        "description": f"High packet count: {conv['source']} -> {conv['destination']}",
                        "severity": "medium",
                        "data": conv
                    })
                    anomalies["risk_score"] += 2

        # Check protocols
        if "results" in analysis and "protocols" in analysis["results"]:
            protocols = analysis["results"]["protocols"]

            # Flag unusual protocols
            suspicious_protocols = ['icmp', 'unknown']
            for protocol, data in protocols.items():
                protocol_lower = protocol.lower()
                if any(susp in protocol_lower for susp in suspicious_protocols):
                    if data.get("packets", 0) > 100:
                        anomalies["anomalies"].append({
                            "type": "suspicious_protocol",
                            "description": f"Unusual protocol activity: {protocol}",
                            "severity": "low",
                            "data": data
                        })
                        anomalies["risk_score"] += 1

        return anomalies

    def comprehensive_pcap_analysis(self, pcap_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a PCAP file

        Args:
            pcap_path: Path to the PCAP file

        Returns:
            Dictionary containing all analysis results
        """
        analysis = {
            "pcap_file": pcap_path,
            "timestamp": None,  # Would be set by caller
            "analyses": {}
        }

        # Basic packet analysis
        analysis["analyses"]["packet_summary"] = self.analyze_pcap_file(pcap_path, 'summary')
        analysis["analyses"]["conversations"] = self.analyze_pcap_file(pcap_path, 'conversations')
        analysis["analyses"]["endpoints"] = self.analyze_pcap_file(pcap_path, 'endpoints')
        analysis["analyses"]["protocols"] = self.analyze_pcap_file(pcap_path, 'protocols')

        # Protocol-specific analysis
        analysis["analyses"]["http_traffic"] = self.extract_http_traffic(pcap_path)
        analysis["analyses"]["dns_traffic"] = self.analyze_dns_traffic(pcap_path)

        # Anomaly detection
        analysis["analyses"]["anomalies"] = self.detect_anomalies(pcap_path)

        return analysis