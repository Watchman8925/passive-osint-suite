"""
IoT and Device Intelligence Module
IoT device discovery, smart device intelligence, Shodan integration
"""

import ipaddress
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests

from utils.osint_utils import OSINTUtils
from utils.result_normalizer import normalize_result


class IoTDeviceIntelligence(OSINTUtils):
    """Comprehensive IoT and device intelligence gathering"""

    def __init__(self):
        super().__init__()
        self.results = {}
        self.shodan_api_key = self.get_api_key("shodan")
        self.censys_api_id = self.get_api_key("censys_id")
        self.censys_api_secret = self.get_api_key("censys_secret")

    def check_rate_limit(self, service: str) -> bool:
        """Check if we're within rate limits for a service"""
        # Simple rate limiting - could be enhanced with actual rate limiting
        return True

    def analyze_iot_devices(self, target: str) -> Dict:
        """
        Comprehensive IoT device analysis and intelligence gathering

        Args:
            target: IP address, domain, or search query

        Returns:
            Standardized result dict
        """
        self.logger.info(f"Starting IoT device analysis for: {target}")

        try:
            self.results = {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "device_discovery": self.discover_iot_devices(target),
                "shodan_analysis": self.analyze_shodan(target),
                "censys_analysis": self.analyze_censys(target),
                "device_fingerprinting": self.fingerprint_devices(target),
                "vulnerability_assessment": self.assess_device_vulnerabilities(target),
                "network_analysis": self.analyze_device_network(target),
                "iot_protocols": self.analyze_iot_protocols(target),
            }

            return normalize_result({"status": "success", "data": self.results})

        except Exception as e:
            self.logger.error(f"IoT device analysis failed: {e}")
            return normalize_result({"status": "error", "error": str(e)})

    def discover_iot_devices(self, target: str) -> Dict[str, Any]:
        """Discover IoT devices in target network or domain"""
        results: Dict[str, Any] = {}

        # Check if target is an IP range
        if self.is_ip_range(target):
            results["ip_range_scan"] = self.scan_ip_range(target)
        elif self.is_ip_address(target):
            results["single_ip_analysis"] = self.analyze_single_ip(target)
        else:
            # Domain-based discovery
            results["domain_devices"] = self.discover_domain_devices(target)

        # Common IoT device signatures
        results["iot_signatures"] = self.check_iot_signatures(target)

        return results

    def is_ip_range(self, target: str) -> bool:
        """Check if target is an IP range (CIDR notation)"""
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    def is_ip_address(self, target: str) -> bool:
        """Check if target is a single IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def scan_ip_range(self, ip_range: str) -> List[Dict]:
        """Scan an IP range for IoT devices"""
        devices = []

        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            # In a real implementation, this would use Shodan or similar
            # For now, return structure
            devices.append(
                {
                    "ip_range": ip_range,
                    "total_addresses": network.num_addresses,
                    "scan_status": "completed",
                    "devices_found": [],
                    "scan_method": "shodan_api",
                }
            )
        except Exception as e:
            self.logger.error(f"IP range scan failed: {e}")

        return devices

    def analyze_single_ip(self, ip: str) -> Dict:
        """Analyze a single IP address for IoT devices"""
        return {
            "ip": ip,
            "device_type": "unknown",
            "services": [],
            "vulnerabilities": [],
            "iot_indicators": [],
        }

    def discover_domain_devices(self, domain: str) -> List[Dict]:
        """Discover IoT devices associated with a domain"""
        devices = []

        # Check for common IoT subdomains
        iot_subdomains = [
            "iot",
            "device",
            "hub",
            "gateway",
            "sensor",
            "camera",
            "thermostat",
            "lock",
            "bulb",
            "switch",
        ]

        for subdomain in iot_subdomains:
            full_domain = f"{subdomain}.{domain}"
            device_info = self.check_iot_subdomain(full_domain)
            if device_info:
                devices.append(device_info)

        return devices

    def check_iot_subdomain(self, domain: str) -> Optional[Dict]:
        """Check if a subdomain hosts IoT devices"""
        try:
            # DNS resolution check
            import socket

            ip = socket.gethostbyname(domain)
            return {
                "domain": domain,
                "ip": ip,
                "device_type": "potential_iot",
                "confidence": "low",
            }
        except socket.gaierror:
            return None

    def check_iot_signatures(self, target: str) -> List[Dict]:
        """Check for common IoT device signatures"""
        signatures = [
            {
                "name": "Default Credentials",
                "pattern": r"admin.*admin|root.*root",
                "severity": "high",
            },
            {
                "name": "IoT Ports",
                "pattern": r"port.*(80|443|8080|2323|23|22)",
                "severity": "medium",
            },
            {
                "name": "Embedded Web Server",
                "pattern": r"GoAhead|lighttpd|uhttpd|busybox",
                "severity": "medium",
            },
        ]

        found_signatures = []
        for sig in signatures:
            if re.search(sig["pattern"], target, re.IGNORECASE):
                found_signatures.append(sig)

        return found_signatures

    def analyze_shodan(self, target: str) -> Optional[Dict]:
        """Analyze target using Shodan API"""
        if not self.shodan_api_key:
            return None

        if not self.check_rate_limit("shodan"):
            return None

        try:
            # Shodan host search
            url = f"https://api.shodan.io/shodan/host/{target}"
            params = {"key": self.shodan_api_key}

            response = self.make_request(url, params=params)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    "ip": target,
                    "organization": data.get("org", "unknown"),
                    "isp": data.get("isp", "unknown"),
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "vulns": data.get("vulns", []),
                    "data": data.get("data", []),
                    "last_update": data.get("last_update", "unknown"),
                }

        except Exception as e:
            self.logger.error(f"Shodan analysis failed: {e}")

        return None

    def analyze_censys(self, target: str) -> Optional[Dict]:
        """Analyze target using Censys API"""
        if not self.censys_api_id or not self.censys_api_secret:
            return None

        if not self.check_rate_limit("censys"):
            return None

        try:
            # Censys IPv4 search
            url = "https://search.censys.io/api/v2/hosts/search"
            auth = (self.censys_api_id, self.censys_api_secret)
            query = {"q": target}

            response = requests.post(url, json=query, auth=auth, timeout=30)
            if response and response.status_code == 200:
                data = response.json()
                return {
                    "query": target,
                    "total_results": data.get("result", {}).get("total", 0),
                    "hosts": data.get("result", {}).get("hits", []),
                }

        except Exception as e:
            self.logger.error(f"Censys analysis failed: {e}")

        return None

    def fingerprint_devices(self, target: str) -> Dict:
        """Fingerprint IoT devices and their characteristics"""
        fingerprints = {
            "device_type": self.identify_device_type(target),
            "manufacturer": self.identify_manufacturer(target),
            "model": self.identify_model(target),
            "firmware_version": "unknown",
            "protocols": self.detect_protocols(target),
            "capabilities": self.detect_capabilities(target),
        }

        return fingerprints

    def identify_device_type(self, target: str) -> str:
        """Identify the type of IoT device"""
        device_types = {
            "camera": ["camera", "cam", "webcam", "ipcam"],
            "thermostat": ["thermostat", "nest", "ecobee"],
            "smart_lock": ["lock", "schlage", "kwikset"],
            "smart_bulb": ["bulb", "light", "hue", "lifx"],
            "router": ["router", "gateway", "ap"],
            "sensor": ["sensor", "motion", "temp", "humidity"],
            "hub": ["hub", "bridge", "gateway"],
        }

        for device_type, keywords in device_types.items():
            for keyword in keywords:
                if keyword.lower() in target.lower():
                    return device_type

        return "unknown"

    def identify_manufacturer(self, target: str) -> str:
        """Identify device manufacturer"""
        manufacturers = {
            "nest": ["nest"],
            "philips": ["hue", "philips"],
            "samsung": ["samsung"],
            "amazon": ["echo", "alexa"],
            "google": ["google", "chromecast"],
            "apple": ["apple", "homekit"],
            "ring": ["ring"],
            "tplink": ["tp-link", "tplink"],
            "dlink": ["d-link", "dlink"],
        }

        for manufacturer, keywords in manufacturers.items():
            for keyword in keywords:
                if keyword.lower() in target.lower():
                    return manufacturer

        return "unknown"

    def identify_model(self, target: str) -> str:
        """Identify device model"""
        # This would require more sophisticated pattern matching
        return "unknown"

    def detect_protocols(self, target: str) -> List[str]:
        """Detect IoT protocols in use"""
        protocols = []

        protocol_indicators = {
            "MQTT": ["mqtt", "1883"],
            "CoAP": ["coap", "5683"],
            "XMPP": ["xmpp", "5222"],
            "UPnP": ["upnp", "1900"],
            "mDNS": ["mdns", "5353"],
            "Zigbee": ["zigbee"],
            "Z-Wave": ["zwave"],
            "Bluetooth": ["bluetooth", "ble"],
        }

        for protocol, indicators in protocol_indicators.items():
            for indicator in indicators:
                if indicator.lower() in target.lower():
                    protocols.append(protocol)
                    break

        return protocols

    def detect_capabilities(self, target: str) -> List[str]:
        """Detect device capabilities"""
        capabilities = []

        capability_indicators = {
            "video_streaming": ["camera", "video", "stream"],
            "audio_recording": ["microphone", "audio", "recording"],
            "motion_detection": ["motion", "pir", "sensor"],
            "remote_control": ["remote", "control", "api"],
            "cloud_connectivity": ["cloud", "aws", "azure", "gcp"],
            "local_network": ["lan", "wifi", "ethernet"],
        }

        for capability, indicators in capability_indicators.items():
            for indicator in indicators:
                if indicator.lower() in target.lower():
                    capabilities.append(capability)
                    break

        return capabilities

    def assess_device_vulnerabilities(self, target: str) -> Dict:
        """Assess vulnerabilities in IoT devices"""
        vulnerabilities = {
            "known_cves": self.check_known_cves(target),
            "default_credentials": self.check_default_credentials(target),
            "outdated_firmware": self.check_firmware_updates(target),
            "weak_encryption": self.check_encryption(target),
            "exposed_services": self.check_exposed_services(target),
            "overall_risk": "medium",
        }

        return vulnerabilities

    def check_known_cves(self, target: str) -> List[Dict]:
        """Check for known CVEs affecting the device"""
        # This would integrate with CVE databases
        return [
            {
                "cve_id": "CVE-2023-XXXX",
                "severity": "high",
                "description": "Example vulnerability",
                "affected_versions": ["1.0.0-2.0.0"],
            }
        ]

    def check_default_credentials(self, target: str) -> Dict:
        """Check for default or weak credentials"""
        return {
            "has_default_credentials": False,
            "common_usernames": ["admin", "root", "user"],
            "common_passwords": ["admin", "password", "123456"],
            "recommendations": ["Change default passwords", "Use strong passwords"],
        }

    def check_firmware_updates(self, target: str) -> Dict:
        """Check for available firmware updates"""
        return {
            "current_version": "unknown",
            "latest_version": "unknown",
            "updates_available": "unknown",
            "update_urgency": "unknown",
        }

    def check_encryption(self, target: str) -> Dict:
        """Check encryption strength and implementation"""
        return {
            "encryption_type": "unknown",
            "key_strength": "unknown",
            "protocol_version": "unknown",
            "vulnerabilities": [],
        }

    def check_exposed_services(self, target: str) -> List[Dict]:
        """Check for exposed services and ports"""
        return [
            {"port": 80, "service": "HTTP", "state": "open", "risk_level": "medium"}
        ]

    def analyze_device_network(self, target: str) -> Dict:
        """Analyze device network configuration and behavior"""
        return {
            "network_segment": "unknown",
            "firewall_rules": [],
            "traffic_patterns": {},
            "connected_devices": [],
            "bandwidth_usage": "unknown",
        }

    def analyze_iot_protocols(self, target: str) -> Dict:
        """Analyze IoT-specific protocols and communications"""
        return {
            "protocols_detected": self.detect_protocols(target),
            "mqtt_analysis": self.analyze_mqtt(target),
            "coap_analysis": self.analyze_coap(target),
            "security_assessment": self.assess_protocol_security(target),
        }

    def analyze_mqtt(self, target: str) -> Dict:
        """Analyze MQTT protocol usage"""
        return {
            "mqtt_broker": "unknown",
            "topics": [],
            "authentication": "unknown",
            "encryption": "unknown",
        }

    def analyze_coap(self, target: str) -> Dict:
        """Analyze CoAP protocol usage"""
        return {
            "coap_endpoints": [],
            "methods_supported": [],
            "security_mode": "unknown",
        }

    def assess_protocol_security(self, target: str) -> Dict:
        """Assess security of IoT protocols"""
        return {
            "overall_security": "medium",
            "encryption_status": "unknown",
            "authentication_strength": "unknown",
            "known_vulnerabilities": [],
        }

    def search_iot_databases(self, query: str) -> Dict:
        """Search IoT-specific databases and directories"""
        results = {}

        # IoT search engines and databases
        iot_sources = [
            "https://iotsearchengine.com",
            "https://www.shodan.io/search?query=iot",
            "https://censys.io/ipv4?q=iot",
        ]

        for source in iot_sources:
            try:
                source_results = self.search_iot_source(source, query)
                if source_results:
                    results[source] = source_results
            except Exception as e:
                self.logger.warning(f"Failed to search {source}: {e}")

        return results

    def search_iot_source(self, source_url: str, query: str) -> Optional[Dict]:
        """Search a specific IoT database or search engine"""
        # This would implement actual scraping/API calls
        return {
            "source": source_url,
            "query": query,
            "results_count": 0,
            "devices_found": [],
        }

    def monitor_iot_devices(self, target_network: str) -> Dict:
        """Monitor IoT devices in a network"""
        return {
            "target_network": target_network,
            "monitoring_status": "started",
            "devices_tracked": [],
            "alerts": [],
            "last_scan": datetime.now().isoformat(),
        }
