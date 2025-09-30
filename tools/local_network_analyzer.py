"""
Local Network Analysis Module

This module provides local network analysis capabilities:
- Network interface enumeration
- Local network scanning
- Connection analysis
- Port analysis
- Network traffic patterns
- Local service discovery
"""

import socket
import subprocess
import platform
from typing import Dict, List, Optional, Any
import psutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from utils.osint_utils import OSINTUtils


class LocalNetworkAnalyzer(OSINTUtils):
    """Analyze local network configuration and connections"""

    def __init__(self):
        super().__init__()
        self.system = platform.system().lower()

    def get_network_interfaces(self) -> Dict[str, Any]:
        """Get information about all network interfaces"""
        interfaces = {}

        try:
            import netifaces

            for interface in netifaces.interfaces():
                interface_info = {"name": interface, "addresses": {}}

                # Get addresses for each interface
                try:
                    addresses = netifaces.ifaddresses(interface)
                    for addr_family, addr_list in addresses.items():
                        if addr_family == netifaces.AF_INET:
                            interface_info["addresses"]["ipv4"] = addr_list
                        elif addr_family == netifaces.AF_INET6:
                            interface_info["addresses"]["ipv6"] = addr_list
                        elif addr_family == netifaces.AF_LINK:
                            interface_info["addresses"]["mac"] = addr_list
                except Exception:
                    pass

                interfaces[interface] = interface_info

        except ImportError:
            # Fallback to psutil
            net_interfaces = psutil.net_if_addrs()
            for interface_name, addresses in net_interfaces.items():
                interface_info = {
                    "name": interface_name,
                    "addresses": {"ipv4": [], "ipv6": [], "mac": []},
                }

                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        interface_info["addresses"]["ipv4"].append(
                            {"addr": addr.address, "netmask": addr.netmask}
                        )
                    elif addr.family == socket.AF_INET6:
                        interface_info["addresses"]["ipv6"].append(
                            {"addr": addr.address, "netmask": addr.netmask}
                        )
                    elif addr.family == psutil.AF_LINK:
                        interface_info["addresses"]["mac"].append(
                            {"addr": addr.address}
                        )

                interfaces[interface_name] = interface_info

        return interfaces

    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get current network connections"""
        connections = []

        try:
            net_connections = psutil.net_connections(kind="inet")

            for conn in net_connections:
                connection_info = {
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}"
                    if conn.laddr
                    else None,
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}"
                    if conn.raddr
                    else None,
                    "status": conn.status,
                    "pid": conn.pid,
                }

                # Get process information if available
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        connection_info["process"] = {
                            "name": process.name(),
                            "exe": process.exe(),
                            "cmdline": process.cmdline(),
                        }
                    except Exception:
                        connection_info["process"] = {"name": "unknown"}

                connections.append(connection_info)

        except Exception as e:
            connections = [{"error": str(e)}]

        return connections

    def scan_local_ports(
        self, host: str = "127.0.0.1", ports: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Scan ports on a local host"""
        if ports is None:
            # Common ports to check
            ports = [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                135,
                139,
                143,
                443,
                445,
                993,
                995,
                3306,
                3389,
            ]

        results = {
            "host": host,
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
        }

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    return {"port": port, "status": "open"}
                else:
                    return {"port": port, "status": "closed"}
            except Exception:
                return {"port": port, "status": "filtered"}

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result["status"] == "open":
                    results["open_ports"].append(result["port"])
                elif result["status"] == "closed":
                    results["closed_ports"].append(result["port"])
                else:
                    results["filtered_ports"].append(result["port"])

        return results

    def get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        stats = {}

        try:
            net_stats = psutil.net_io_counters(pernic=True)

            for interface, counters in net_stats.items():
                stats[interface] = {
                    "bytes_sent": counters.bytes_sent,
                    "bytes_recv": counters.bytes_recv,
                    "packets_sent": counters.packets_sent,
                    "packets_recv": counters.packets_recv,
                    "errin": counters.errin,
                    "errout": counters.errout,
                    "dropin": counters.dropin,
                    "dropout": counters.dropout,
                }

        except Exception as e:
            stats["error"] = str(e)

        return stats

    def discover_local_services(self) -> List[Dict[str, Any]]:
        """Discover services running on common ports"""
        services = []
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }

        port_scan = self.scan_local_ports()

        for port in port_scan["open_ports"]:
            service_info = {
                "port": port,
                "service": common_ports.get(port, "Unknown"),
                "protocol": "tcp",
            }

            # Try to get service banner
            banner = self._get_service_banner("127.0.0.1", port)
            if banner:
                service_info["banner"] = banner

            services.append(service_info)

        return services

    def _get_service_banner(
        self, host: str, port: int, timeout: float = 2
    ) -> Optional[str]:
        """Get service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send a simple probe
            if port in [80, 8080, 443, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()

            return banner[:200]  # Limit banner length

        except Exception:
            return None

    def analyze_network_traffic(self, duration: int = 10) -> Dict[str, Any]:
        """Analyze network traffic patterns over a time period"""
        initial_stats = self.get_network_stats()
        time.sleep(duration)
        final_stats = self.get_network_stats()

        analysis = {"duration_seconds": duration, "interfaces": {}}

        for interface in initial_stats:
            if interface in final_stats and interface != "error":
                initial = initial_stats[interface]
                final = final_stats[interface]

                analysis["interfaces"][interface] = {
                    "bytes_sent_per_sec": (final["bytes_sent"] - initial["bytes_sent"])
                    / duration,
                    "bytes_recv_per_sec": (final["bytes_recv"] - initial["bytes_recv"])
                    / duration,
                    "packets_sent_per_sec": (
                        final["packets_sent"] - initial["packets_sent"]
                    )
                    / duration,
                    "packets_recv_per_sec": (
                        final["packets_recv"] - initial["packets_recv"]
                    )
                    / duration,
                    "total_bytes": final["bytes_sent"] + final["bytes_recv"],
                    "total_packets": final["packets_sent"] + final["packets_recv"],
                }

        return analysis

    def get_routing_table(self) -> List[Dict[str, Any]]:
        """Get system routing table"""
        routes = []

        try:
            if self.system == "windows":
                # Windows routing table
                result = subprocess.run(
                    ["route", "print"], capture_output=True, text=True, timeout=10
                )
                # Parse Windows route output (simplified)
                routes = [{"raw": result.stdout}]

            else:
                # Unix-like systems
                result = subprocess.run(
                    ["netstat", "-rn"], capture_output=True, text=True, timeout=10
                )
                lines = result.stdout.strip().split("\n")

                for line in lines[2:]:  # Skip headers
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 8:
                        route_info = {
                            "destination": parts[0],
                            "gateway": parts[1],
                            "genmask": parts[2],
                            "flags": parts[3],
                            "mss": parts[4],
                            "window": parts[5],
                            "irtt": parts[6],
                            "iface": parts[7],
                        }
                        routes.append(route_info)

        except Exception as e:
            routes = [{"error": str(e)}]

        return routes

    def check_network_connectivity(
        self, targets: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Check connectivity to various network targets"""
        if targets is None:
            targets = [
                "8.8.8.8",  # Google DNS
                "1.1.1.1",  # Cloudflare DNS
                "208.67.222.222",  # OpenDNS
                "google.com",
                "cloudflare.com",
            ]

        results = {"targets": {}}

        def check_target(target):
            try:
                # Try to resolve
                ip = socket.gethostbyname(target)
                results["targets"][target] = {
                    "resolvable": True,
                    "ip": ip,
                    "reachable": False,
                }

                # Try to connect
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, 80))
                sock.close()

                results["targets"][target]["reachable"] = result == 0

            except socket.gaierror:
                results["targets"][target] = {"resolvable": False, "reachable": False}
            except Exception as e:
                results["targets"][target] = {"error": str(e)}

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_target, target) for target in targets]
            for future in as_completed(futures):
                pass  # Results are stored in the shared dict

        return results

    def get_dns_servers(self) -> List[str]:
        """Get configured DNS servers"""
        dns_servers = []

        try:
            if self.system == "windows":
                # Windows DNS servers
                result = subprocess.run(
                    ["ipconfig", "/all"], capture_output=True, text=True, timeout=10
                )
                # Parse DNS servers from output
                for line in result.stdout.split("\n"):
                    if "DNS Servers" in line:
                        # Extract IP after colon
                        parts = line.split(":")
                        if len(parts) > 1:
                            dns_servers.append(parts[1].strip())

            else:
                # Unix-like systems - check /etc/resolv.conf
                try:
                    with open("/etc/resolv.conf", "r") as f:
                        for line in f:
                            if line.startswith("nameserver"):
                                dns_servers.append(line.split()[1])
                except Exception:
                    pass

        except Exception as e:
            dns_servers = [f"Error: {str(e)}"]

        return dns_servers

    def generate_network_report(self) -> str:
        """Generate a comprehensive network analysis report"""
        report = "Local Network Analysis Report\n"
        report += "=" * 40 + "\n\n"

        # Network interfaces
        interfaces = self.get_network_interfaces()
        report += "Network Interfaces:\n"
        report += "-" * 20 + "\n"
        for name, info in interfaces.items():
            report += f"Interface: {name}\n"
            for addr_type, addresses in info.get("addresses", {}).items():
                if addresses:
                    report += f"  {addr_type.upper()}: {addresses}\n"
            report += "\n"

        # Network connections
        connections = self.get_network_connections()
        report += (
            f"Active Connections: {len([c for c in connections if 'error' not in c])}\n"
        )
        report += "-" * 20 + "\n"

        # Open ports
        port_scan = self.scan_local_ports()
        report += f"Open Ports: {len(port_scan['open_ports'])}\n"
        if port_scan["open_ports"]:
            report += f"Ports: {', '.join(map(str, port_scan['open_ports']))}\n"
        report += "\n"

        # DNS servers
        dns_servers = self.get_dns_servers()
        report += f"DNS Servers: {', '.join(dns_servers)}\n\n"

        # Connectivity check
        connectivity = self.check_network_connectivity()
        reachable = sum(
            1
            for target in connectivity["targets"].values()
            if target.get("reachable", False)
        )
        total = len(connectivity["targets"])
        report += f"Network Connectivity: {reachable}/{total} targets reachable\n"

        return report
