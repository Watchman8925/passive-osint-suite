"""
Service Registry for OSINT Suite
Centralized management of external services and their API keys
"""

from typing import Dict, List, Optional

from utils.osint_utils import OSINTUtils


class ServiceRegistry:
    """Centralized registry for external services and API management"""

    def __init__(self):
        self.utils = OSINTUtils()
        self._service_map = self._build_service_map()

    def _build_service_map(self) -> Dict:
        """Build mapping of services to their configuration"""
        return {
            # Intelligence & Security Services
            "shodan": {
                "api_key": "SHODAN_API_KEY",
                "base_url": "https://api.shodan.io",
                "rate_limit": 1,  # requests per second
                "description": "Shodan internet search engine",
            },
            "alienvault": {
                "api_key": "ALIENVAULT_OTX_API_KEY",
                "base_url": "https://otx.alienvault.com/api/v1",
                "rate_limit": 2,
                "description": "AlienVault Open Threat Exchange",
            },
            "greynoise": {
                "api_key": "GREYNOISE_API_KEY",
                "base_url": "https://api.greynoise.io/v3",
                "rate_limit": 10,
                "description": "GreyNoise IP reputation service",
            },
            "virustotal": {
                "api_key": "VIRUSTOTAL_API_KEY",
                "base_url": "https://www.virustotal.com/api/v3",
                "rate_limit": 4,
                "description": "VirusTotal malware analysis",
            },
            # Domain & Certificate Services
            "securitytrails": {
                "api_key": "SECURITYTRAILS_API_KEY",
                "base_url": "https://api.securitytrails.com/v1",
                "rate_limit": 1,
                "description": "SecurityTrails domain intelligence",
            },
            "hostio": {
                "api_key": "HOSTIO_API_KEY",
                "base_url": "https://host.io/api",
                "rate_limit": 10,
                "description": "Host.io domain intelligence",
            },
            "projectdiscovery": {
                "api_key": "PROJECTDISCOVERY_API_KEY",
                "base_url": "https://api.projectdiscovery.io",
                "rate_limit": 5,
                "description": "Project Discovery security tools",
            },
            # Breach & Leak Services
            "intelx": {
                "api_key": "INTELX_API_KEY",
                "base_url": "https://2.intelx.io",
                "rate_limit": 2,
                "description": "Intelligence X dark web search",
            },
            "dehashed": {
                "api_key": "DEHASHED_API_KEY",
                "username": "DEHASHED_USERNAME",
                "base_url": "https://api.dehashed.com",
                "rate_limit": 1,
                "description": "DeHashed breach database",
            },
            "hibp": {
                "api_key": "HIBP_API_KEY",
                "base_url": "https://haveibeenpwned.com/api/v3",
                "rate_limit": 1,
                "description": "Have I Been Pwned breach check",
            },
            "botscout": {
                "api_key": "BOTSCOUT_API_KEY",
                "base_url": "https://botscout.com/api",
                "rate_limit": 10,
                "description": "BotScout bot detection",
            },
            "citadel": {
                "api_key": "CITADEL_API_KEY",
                "base_url": "https://citadel.pw/api",
                "rate_limit": 5,
                "description": "Citadel breach database",
            },
            "grayhatwarfare": {
                "api_key": "GRAYHATWARFARE_API_KEY",
                "base_url": "https://buckets.grayhatwarfare.com/api",
                "rate_limit": 10,
                "description": "GrayHatWarfare bucket discovery",
            },
            # Social & Search Services
            "hunter": {
                "api_key": "HUNTER_API_KEY",
                "base_url": "https://api.hunter.io/v2",
                "rate_limit": 10,
                "description": "Hunter.io email finder",
            },
            "googlesearch": {
                "api_key": "GOOGLESEARCH_API_KEY",
                "cx": "GOOGLESEARCH_CX",
                "base_url": "https://www.googleapis.com/customsearch/v1",
                "rate_limit": 100,
                "description": "Google Custom Search",
            },
            "pastebin": {
                "api_key": "PASTEBIN_API_KEY",
                "base_url": "https://pastebin.com/api",
                "rate_limit": 10,
                "description": "Pastebin API",
            },
            "socialprofiles_google": {
                "api_key": "SOCIALPROFILES_GOOGLE_API_KEY",
                "base_url": "https://www.googleapis.com/plus/v1",
                "rate_limit": 10,
                "description": "Google+ API for social profiles",
            },
            # Cryptocurrency Services
            "etherscan": {
                "api_key": "ETHERSCAN_API_KEY",
                "base_url": "https://api.etherscan.io/api",
                "rate_limit": 5,
                "description": "Etherscan blockchain explorer",
            },
            "coinmarketcap": {
                "api_key": "COINMARKETCAP_API_KEY",
                "base_url": "https://pro-api.coinmarketcap.com/v1",
                "rate_limit": 10,
                "description": "CoinMarketCap cryptocurrency data",
            },
            # Aviation Services
            "flightaware": {
                "api_key": "FLIGHTAWARE_API_KEY",
                "username": "FLIGHTAWARE_USERNAME",
                "base_url": "https://flightxml.flightaware.com/json/FlightXML3",
                "rate_limit": 1,
                "description": "FlightAware flight tracking",
            },
            # Geographic Services
            "opencage": {
                "api_key": "OPENCAGE_API_KEY",
                "base_url": "https://api.opencagedata.com/geocode/v1",
                "rate_limit": 2500,
                "description": "OpenCage geocoding service",
            },
            "mapbox": {
                "api_key": "MAPBOX_API_KEY",
                "base_url": "https://api.mapbox.com",
                "rate_limit": 60000,
                "description": "Mapbox mapping service",
            },
        }

    def get_service_config(self, service_name: str) -> Optional[Dict]:
        """Get configuration for a specific service"""
        return self._service_map.get(service_name.lower())

    def get_api_key(self, service_name: str) -> Optional[str]:
        """Get API key for a service"""
        config = self.get_service_config(service_name)
        if not config:
            return None

        key_name = config.get("api_key")
        if key_name:
            return self.utils.get_api_key(key_name)

        return None

    def get_service_url(self, service_name: str, endpoint: str = "") -> Optional[str]:
        """Get full URL for a service endpoint"""
        config = self.get_service_config(service_name)
        if not config:
            return None

        base_url = config.get("base_url", "")
        if endpoint:
            return f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        return base_url

    def get_rate_limit(self, service_name: str) -> int:
        """Get rate limit for a service (requests per minute)"""
        config = self.get_service_config(service_name)
        return config.get("rate_limit", 1) if config else 1

    def is_service_available(self, service_name: str) -> bool:
        """Check if a service is configured and available"""
        config = self.get_service_config(service_name)
        if not config:
            return False

        # Check if API key is available
        api_key = self.get_api_key(service_name)
        if not api_key:
            return False

        # Check for additional required credentials
        if "username" in config:
            username_key = config["username"]
            username = self.utils.get_api_key(username_key)
            if not username:
                return False

        return True

    def list_available_services(self) -> List[str]:
        """List all services that are configured and available"""
        return [
            name for name in self._service_map.keys() if self.is_service_available(name)
        ]

    def list_all_services(self) -> List[str]:
        """List all registered services"""
        return list(self._service_map.keys())

    def get_service_info(self, service_name: str) -> Optional[Dict]:
        """Get detailed information about a service"""
        config = self.get_service_config(service_name)
        if not config:
            return None

        return {
            "name": service_name,
            "description": config.get("description", ""),
            "available": self.is_service_available(service_name),
            "rate_limit": self.get_rate_limit(service_name),
            "base_url": config.get("base_url", ""),
            "has_api_key": bool(self.get_api_key(service_name)),
        }


# Global service registry instance
service_registry = ServiceRegistry()
