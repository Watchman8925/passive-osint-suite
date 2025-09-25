#!/usr/bin/env python3
"""
Local Network Analyzer Module
Network analysis and reconnaissance for local environments.
"""

import logging
import socket
import ipaddress
import subprocess
import platform
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re

logger = logging.getLogger(__name__)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not available - system network info limited")

class LocalNetworkAnalyzer:
    """Advanced local network analyzer"""

    def __init__(self):
        self.enabled = True
        self.timeout = 1.0
        self.max_workers = 20

        # Common service ports to check
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            5900: "VNC"
        }

        logger.info("LocalNetworkAnalyzer initialized with network analysis capabilities")

    def analyze_network(self, network_range: str) -> Dict[str, Any]:
        """Analyze local network for active hosts and services"""
        try:
            results = {
                "network_range": network_range,
                "hosts": [],
                "services": [],
                "analyzed": True,
                "timestamp": time.time(),
                "scan_method": "basic_port_scan"
            }

            # Parse network range
            try:
                network = ipaddress.ip_network(network_range, strict=False)
            except ValueError:
                return {
                    "network_range": network_range,
                    "hosts": [],
                    "services": [],
                    "analyzed": False,
                    "error": "Invalid network range"
                }

            # Get local network information
            local_info = self._get_local_network_info()
            results["local_info"] = local_info

            # Scan network for active hosts
            active_hosts = []
            if isinstance(network, ipaddress.IPv4Network):
                active_hosts = self._scan_network(network)
            results["hosts"] = active_hosts

            # Scan services on active hosts
            services = self._scan_services(active_hosts)
            results["services"] = services

            # Analyze results
            results["analysis"] = self._analyze_network_results(results)

            return results

        except Exception as e:
            logger.error(f"Failed to analyze network {network_range}: {e}")
            return {
                "network_range": network_range,
                "hosts": [],
                "services": [],
                "analyzed": False,
                "error": str(e)
            }

    def _get_local_network_info(self) -> Dict[str, Any]:
        """Get local network interface information"""
        info = {
            "hostname": socket.gethostname(),
            "interfaces": []
        }

        try:
            # Get local IP addresses
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            info["local_ip"] = local_ip

            # Get network interfaces
            if HAS_PSUTIL:
                interfaces = psutil.net_if_addrs()  # type: ignore
                for interface_name, addresses in interfaces.items():
                    interface_info = {"name": interface_name, "addresses": []}
                    for addr in addresses:
                        if addr.family == socket.AF_INET:  # IPv4
                            interface_info["addresses"].append({
                                "ip": addr.address,
                                "netmask": addr.netmask,
                                "family": "IPv4"
                            })
                        elif addr.family == socket.AF_INET6:  # IPv6
                            interface_info["addresses"].append({
                                "ip": addr.address,
                                "netmask": addr.netmask,
                                "family": "IPv6"
                            })
                    info["interfaces"].append(interface_info)

        except Exception as e:
            logger.warning(f"Could not get local network info: {e}")

        return info

    def _scan_network(self, network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
        """Scan network for active hosts"""
        active_hosts = []

        def ping_host(ip: str) -> Optional[Dict[str, Any]]:
            try:
                # Use system ping command
                param = "-n" if platform.system().lower() == "windows" else "-c"
                command = ["ping", param, "1", "-W", "1", ip]

                result = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=2
                )

                if result.returncode == 0:
                    # Try to resolve hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        hostname = None

                    return {
                        "ip": ip,
                        "hostname": hostname,
                        "status": "active",
                        "response_time": "unknown"
                    }

            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass

            return None

        # Scan network (limit to reasonable size)
        if network.num_addresses > 1024:
            logger.warning(f"Network {network} is too large ({network.num_addresses} hosts), limiting scan")
            # Only scan first 256 addresses
            hosts_to_scan = [str(network.network_address + i) for i in range(min(256, network.num_addresses))]
        else:
            hosts_to_scan = [str(ip) for ip in network.hosts()]

        # Scan hosts concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(ping_host, ip) for ip in hosts_to_scan]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)

        return active_hosts

    def _scan_services(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for open services on active hosts"""
        services = []

        def scan_host_services(host_info: Dict[str, Any]) -> List[Dict[str, Any]]:
            host_services = []
            ip = host_info["ip"]

            for port, service_name in self.common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((ip, port))

                    if result == 0:  # Port is open
                        host_services.append({
                            "ip": ip,
                            "port": port,
                            "service": service_name,
                            "status": "open"
                        })

                    sock.close()

                except Exception:
                    pass

            return host_services

        # Scan services on all active hosts
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(scan_host_services, host) for host in hosts]

            for future in as_completed(futures):
                host_services = future.result()
                services.extend(host_services)

        return services

    def _analyze_network_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network scan results"""
        analysis = {
            "total_hosts_scanned": len(results.get("hosts", [])),
            "active_hosts": len([h for h in results.get("hosts", []) if h.get("status") == "active"]),
            "total_services": len(results.get("services", [])),
            "service_distribution": {},
            "security_concerns": []
        }

        # Analyze service distribution
        services = results.get("services", [])
        service_counts = {}
        for service in services:
            service_name = service.get("service", "unknown")
            service_counts[service_name] = service_counts.get(service_name, 0) + 1

        analysis["service_distribution"] = service_counts

        # Identify security concerns
        if any(s.get("service") == "Telnet" for s in services):
            analysis["security_concerns"].append("Telnet service detected (insecure)")

        if any(s.get("service") == "FTP" for s in services):
            analysis["security_concerns"].append("FTP service detected (consider SFTP)")

        open_web_servers = [s for s in services if s.get("service") in ["HTTP", "HTTPS"]]
        if len(open_web_servers) > 5:
            analysis["security_concerns"].append("Many web servers detected - potential web farm")

        return analysis

    def detect_anomalies(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect network anomalies in traffic data"""
        try:
            anomalies = []
            detected = False

            # Analyze packet counts if available
            if "packets" in traffic_data:
                packets = traffic_data["packets"]
                if isinstance(packets, list):
                    # Basic anomaly detection
                    packet_counts = {}
                    for packet in packets:
                        src = packet.get("source_ip")
                        if src:
                            packet_counts[src] = packet_counts.get(src, 0) + 1

                    # Detect high traffic sources
                    avg_packets = sum(packet_counts.values()) / len(packet_counts) if packet_counts else 0
                    threshold = avg_packets * 3  # 3x average

                    for ip, count in packet_counts.items():
                        if count > threshold:
                            anomalies.append({
                                "type": "high_traffic",
                                "description": f"IP {ip} has unusually high traffic ({count} packets)",
                                "severity": "medium",
                                "ip": ip,
                                "packet_count": count
                            })
                            detected = True

            # Analyze connection patterns
            if "connections" in traffic_data:
                connections = traffic_data["connections"]
                if isinstance(connections, list):
                    # Detect port scanning
                    port_scan_threshold = 10
                    source_ports = {}

                    for conn in connections:
                        src = conn.get("source_ip")
                        dst_port = conn.get("destination_port")

                        if src and dst_port:
                            if src not in source_ports:
                                source_ports[src] = set()
                            source_ports[src].add(dst_port)

                    for ip, ports in source_ports.items():
                        if len(ports) > port_scan_threshold:
                            anomalies.append({
                                "type": "port_scan",
                                "description": f"IP {ip} attempted connections to {len(ports)} different ports",
                                "severity": "high",
                                "ip": ip,
                                "ports_scanned": len(ports)
                            })
                            detected = True

            # Analyze bandwidth usage
            if "bandwidth" in traffic_data:
                bandwidth = traffic_data["bandwidth"]
                if isinstance(bandwidth, dict):
                    # Simple threshold-based detection
                    if bandwidth.get("total_mb", 0) > 1000:  # 1GB threshold
                        anomalies.append({
                            "type": "high_bandwidth",
                            "description": f"High bandwidth usage detected ({bandwidth.get('total_mb')} MB)",
                            "severity": "low"
                        })
                        detected = True

            return {
                "anomalies": anomalies,
                "detected": detected,
                "anomaly_count": len(anomalies),
                "analysis_timestamp": time.time()
            }

        except Exception as e:
            logger.error(f"Failed to detect network anomalies: {e}")
            return {"anomalies": [], "detected": False, "error": str(e)}

    def get_network_topology(self, network_range: str) -> Dict[str, Any]:
        """Generate network topology information"""
        try:
            # First analyze the network
            analysis = self.analyze_network(network_range)

            topology = {
                "network": network_range,
                "nodes": [],
                "edges": [],
                "generated": True
            }

            # Create nodes from hosts
            for host in analysis.get("hosts", []):
                node = {
                    "id": host["ip"],
                    "type": "host",
                    "hostname": host.get("hostname"),
                    "status": host.get("status", "unknown")
                }
                topology["nodes"].append(node)

            # Create edges from services (host-to-service relationships)
            for service in analysis.get("services", []):
                edge = {
                    "source": service["ip"],
                    "target": f"{service['service']}:{service['port']}",
                    "type": "service",
                    "port": service["port"]
                }
                topology["edges"].append(edge)

                # Add service node if not exists
                service_node = {
                    "id": f"{service['service']}:{service['port']}",
                    "type": "service",
                    "service": service["service"],
                    "port": service["port"]
                }
                if service_node not in topology["nodes"]:
                    topology["nodes"].append(service_node)

            return topology

        except Exception as e:
            logger.error(f"Failed to generate network topology: {e}")
            return {"network": network_range, "nodes": [], "edges": [], "generated": False, "error": str(e)}