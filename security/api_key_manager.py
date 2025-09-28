"""
API Key Configuration Manager
============================

Comprehensive API key configuration, validation, and management system
to ensure flawless operation of all intelligence gathering capabilities.

This manager handles:
- API key discovery and validation
- Service availability testing
- Rate limit management
- Fallback service configuration
- Secure key storage and rotation
- Performance optimization
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
# Import our existing modules
from .secrets_manager import SecretsManager

from transport import ProxiedTransport

logger = logging.getLogger(__name__)


@dataclass
class APIServiceConfig:
    """Configuration for an API service."""

    service_name: str
    service_type: str  # search_engine, social_media, leak_db, geoint, etc.
    api_key_env_var: str
    base_url: str
    endpoints: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    rate_limits: Dict[str, int] = field(default_factory=dict)
    requires_auth: bool = True
    auth_type: str = "api_key"  # api_key, oauth, basic_auth, bearer_token
    test_endpoint: Optional[str] = None
    fallback_services: List[str] = field(default_factory=list)
    is_active: bool = False
    last_tested: Optional[datetime] = None
    error_count: int = 0
    daily_quota: int = 1000
    daily_usage: int = 0


@dataclass
class APIKeyStatus:
    """Status information for an API key."""

    service_name: str
    is_valid: bool
    is_active: bool
    quota_remaining: int
    rate_limit_reset: Optional[datetime]
    last_error: Optional[str]
    performance_score: float
    usage_today: int


class APIConfigurationManager:
    """
    Comprehensive API configuration manager for OSINT operations.

    Ensures all API integrations are properly configured and working
    optimally for intelligence gathering operations.
    """

    def __init__(self):
        self.services = {}
        self.secrets_manager = SecretsManager()
        self.transport = ProxiedTransport()
        self.config_file = Path(
            "/workspaces/passive-osint-suite/config/api_config.json"
        )
        self.status_file = Path(
            "/workspaces/passive-osint-suite/config/api_status.json"
        )

        # Initialize configuration
        self._initialize_services()
        self._load_configuration()

    def _initialize_services(self):
        """Initialize comprehensive API service configurations."""

        # Search Engines & General APIs
        self.services.update(
            {
                "google_custom_search": APIServiceConfig(
                    service_name="Google Custom Search",
                    service_type="search_engine",
                    api_key_env_var="GOOGLE_API_KEY",
                    base_url="https://www.googleapis.com/customsearch/v1",
                    endpoints={"search": "/search", "siterestrict": "/search"},
                    headers={"User-Agent": "OSINT-Research-Tool"},
                    rate_limits={"per_second": 10, "per_day": 100},
                    test_endpoint="/search?key={api_key}&cx=test&q=test",
                    fallback_services=["bing_search", "duckduckgo"],
                    daily_quota=100,
                ),
                "bing_search": APIServiceConfig(
                    service_name="Bing Web Search",
                    service_type="search_engine",
                    api_key_env_var="BING_SEARCH_KEY",
                    base_url="https://api.cognitive.microsoft.com/bing/v7.0",
                    endpoints={
                        "search": "/search",
                        "news": "/news/search",
                        "images": "/images/search",
                    },
                    headers={"Ocp-Apim-Subscription-Key": "{api_key}"},
                    rate_limits={"per_second": 3, "per_month": 1000},
                    test_endpoint="/search?q=test",
                    fallback_services=["google_custom_search", "duckduckgo"],
                    daily_quota=1000,
                ),
                "shodan": APIServiceConfig(
                    service_name="Shodan",
                    service_type="network_intel",
                    api_key_env_var="SHODAN_API_KEY",
                    base_url="https://api.shodan.io",
                    endpoints={
                        "host": "/shodan/host/{ip}",
                        "search": "/shodan/host/search",
                        "count": "/shodan/host/count",
                        "info": "/api-info",
                    },
                    headers={"User-Agent": "OSINT-Scanner"},
                    rate_limits={"per_second": 1, "per_month": 100},
                    test_endpoint="/api-info?key={api_key}",
                    daily_quota=100,
                ),
                "virustotal": APIServiceConfig(
                    service_name="VirusTotal",
                    service_type="threat_intel",
                    api_key_env_var="VIRUSTOTAL_API_KEY",
                    base_url="https://www.virustotal.com/vtapi/v2",
                    endpoints={
                        "url_report": "/url/report",
                        "domain_report": "/domain/report",
                        "ip_report": "/ip-address/report",
                        "file_scan": "/file/scan",
                    },
                    headers={"User-Agent": "OSINT-ThreatIntel"},
                    rate_limits={"per_minute": 4, "per_day": 1000},
                    test_endpoint="/domain/report?apikey={api_key}&domain=google.com",
                    daily_quota=1000,
                ),
                "hibp": APIServiceConfig(
                    service_name="Have I Been Pwned",
                    service_type="breach_intel",
                    api_key_env_var="HIBP_API_KEY",
                    base_url="https://haveibeenpwned.com/api/v3",
                    endpoints={
                        "breachedaccount": "/breachedaccount/{account}",
                        "breaches": "/breaches",
                        "breach": "/breach/{name}",
                        "pasteaccount": "/pasteaccount/{account}",
                    },
                    headers={
                        "hibp-api-key": "{api_key}",
                        "User-Agent": "OSINT-BreachIntel",
                    },
                    rate_limits={"per_minute": 1, "per_day": 1000},
                    test_endpoint="/breaches",
                    daily_quota=1000,
                ),
                "pipl": APIServiceConfig(
                    service_name="Pipl",
                    service_type="people_search",
                    api_key_env_var="PIPL_API_KEY",
                    base_url="https://api.pipl.com/search",
                    endpoints={"search": "/search"},
                    headers={"User-Agent": "OSINT-PeopleSearch"},
                    rate_limits={"per_month": 1000},
                    test_endpoint="/search?key={api_key}&email=test@example.com",
                    daily_quota=100,
                ),
                "clearbit": APIServiceConfig(
                    service_name="Clearbit",
                    service_type="company_intel",
                    api_key_env_var="CLEARBIT_API_KEY",
                    base_url="https://company.clearbit.com/v2",
                    endpoints={"company": "/companies/find", "person": "/people/find"},
                    headers={"Authorization": "Bearer {api_key}"},
                    rate_limits={"per_hour": 600},
                    test_endpoint="/companies/find?domain=google.com",
                    auth_type="bearer_token",
                    daily_quota=600,
                ),
                "hunter_io": APIServiceConfig(
                    service_name="Hunter.io",
                    service_type="email_intel",
                    api_key_env_var="HUNTER_API_KEY",
                    base_url="https://api.hunter.io/v2",
                    endpoints={
                        "domain_search": "/domain-search",
                        "email_finder": "/email-finder",
                        "email_verifier": "/email-verifier",
                    },
                    headers={"User-Agent": "OSINT-EmailIntel"},
                    rate_limits={"per_month": 1000},
                    test_endpoint="/domain-search?domain=google.com&api_key={api_key}",
                    daily_quota=100,
                ),
                "spyse": APIServiceConfig(
                    service_name="Spyse",
                    service_type="network_intel",
                    api_key_env_var="SPYSE_API_KEY",
                    base_url="https://api.spyse.com/v4",
                    endpoints={
                        "domain": "/data/domain/{domain}",
                        "ip": "/data/ip/{ip}",
                        "subdomain": "/data/domain/subdomain/{domain}",
                    },
                    headers={"Authorization": "Bearer {api_key}"},
                    rate_limits={"per_month": 1000},
                    test_endpoint="/data/domain/google.com",
                    auth_type="bearer_token",
                    daily_quota=100,
                ),
                "censys": APIServiceConfig(
                    service_name="Censys",
                    service_type="network_intel",
                    api_key_env_var="CENSYS_API_ID",
                    base_url="https://search.censys.io/api/v2",
                    endpoints={
                        "hosts": "/hosts/search",
                        "certificates": "/certificates/search",
                    },
                    headers={"User-Agent": "OSINT-NetworkIntel"},
                    rate_limits={"per_second": 1, "per_day": 1000},
                    auth_type="basic_auth",
                    test_endpoint="/hosts/search?q=google.com",
                    daily_quota=1000,
                ),
                "securitytrails": APIServiceConfig(
                    service_name="SecurityTrails",
                    service_type="dns_intel",
                    api_key_env_var="SECURITYTRAILS_API_KEY",
                    base_url="https://api.securitytrails.com/v1",
                    endpoints={
                        "domain": "/domain/{domain}",
                        "subdomains": "/domain/{domain}/subdomains",
                        "history": "/history/{domain}/dns/{type}",
                    },
                    headers={"APIKEY": "{api_key}"},
                    rate_limits={"per_month": 50},
                    test_endpoint="/ping",
                    daily_quota=50,
                ),
                "whoisxml": APIServiceConfig(
                    service_name="WhoisXML API",
                    service_type="domain_intel",
                    api_key_env_var="WHOISXML_API_KEY",
                    base_url="https://www.whoisxmlapi.com/whoisserver/WhoisService",
                    endpoints={"whois": "/whois"},
                    headers={"User-Agent": "OSINT-DomainIntel"},
                    rate_limits={"per_month": 1000},
                    test_endpoint="/whois?apiKey={api_key}&domainName=google.com&outputFormat=JSON",
                    daily_quota=100,
                ),
                "urlvoid": APIServiceConfig(
                    service_name="URLVoid",
                    service_type="url_intel",
                    api_key_env_var="URLVOID_API_KEY",
                    base_url="https://api.urlvoid.com/v1",
                    endpoints={"urlreport": "/pay-as-you-go/", "stats": "/stats/"},
                    headers={"User-Agent": "OSINT-URLIntel"},
                    rate_limits={"per_day": 1000},
                    test_endpoint="/stats/?key={api_key}",
                    daily_quota=1000,
                ),
                "ipinfo": APIServiceConfig(
                    service_name="IPInfo",
                    service_type="ip_intel",
                    api_key_env_var="IPINFO_TOKEN",
                    base_url="https://ipinfo.io",
                    endpoints={"ip": "/{ip}", "bulk": "/batch"},
                    headers={"Authorization": "Bearer {api_key}"},
                    rate_limits={"per_month": 50000},
                    test_endpoint="/8.8.8.8?token={api_key}",
                    auth_type="bearer_token",
                    daily_quota=1000,
                ),
                "maxmind": APIServiceConfig(
                    service_name="MaxMind GeoIP2",
                    service_type="geo_intel",
                    api_key_env_var="MAXMIND_LICENSE_KEY",
                    base_url="https://geoip.maxmind.com",
                    endpoints={
                        "city": "/geoip/v2.1/city/{ip}",
                        "country": "/geoip/v2.1/country/{ip}",
                    },
                    headers={"User-Agent": "OSINT-GeoIntel"},
                    rate_limits={"per_second": 1000},
                    auth_type="basic_auth",
                    test_endpoint="/geoip/v2.1/city/8.8.8.8",
                    daily_quota=10000,
                ),
                "twitter_api": APIServiceConfig(
                    service_name="Twitter API v2",
                    service_type="social_media",
                    api_key_env_var="TWITTER_BEARER_TOKEN",
                    base_url="https://api.twitter.com/2",
                    endpoints={
                        "users_by_username": "/users/by/username/{username}",
                        "tweets_search": "/tweets/search/recent",
                        "users_tweets": "/users/{id}/tweets",
                    },
                    headers={"Authorization": "Bearer {api_key}"},
                    rate_limits={"per_15min": 300},
                    auth_type="bearer_token",
                    test_endpoint="/users/me",
                    daily_quota=1000,
                ),
                "telegram_api": APIServiceConfig(
                    service_name="Telegram Bot API",
                    service_type="messaging",
                    api_key_env_var="TELEGRAM_BOT_TOKEN",
                    base_url="https://api.telegram.org/bot{api_key}",
                    endpoints={"getMe": "/getMe", "sendMessage": "/sendMessage"},
                    headers={"Content-Type": "application/json"},
                    rate_limits={"per_second": 30},
                    test_endpoint="/getMe",
                    daily_quota=1000,
                ),
                "openai": APIServiceConfig(
                    service_name="OpenAI API",
                    service_type="ai_llm",
                    api_key_env_var="OPENAI_API_KEY",
                    base_url="https://api.openai.com/v1",
                    endpoints={
                        "chat": "/chat/completions",
                        "completions": "/completions",
                        "models": "/models",
                        "embeddings": "/embeddings",
                    },
                    headers={
                        "Authorization": "Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    rate_limits={"per_minute": 60, "per_day": 10000},
                    test_endpoint="/models",
                    auth_type="bearer_token",
                    daily_quota=10000,
                ),
            }
        )

    def _load_configuration(self):
        """Load configuration from file."""
        try:
            if self.config_file.exists():
                with open(self.config_file, "r") as f:
                    config_data = json.load(f)

                # Update service configurations
                for service_name, config in config_data.items():
                    if service_name in self.services:
                        # Update existing service configuration
                        service = self.services[service_name]
                        service.is_active = config.get("is_active", False)
                        service.daily_usage = config.get("daily_usage", 0)
                        service.error_count = config.get("error_count", 0)

                        # Parse last_tested datetime
                        if config.get("last_tested"):
                            service.last_tested = datetime.fromisoformat(
                                config["last_tested"]
                            )

            # Load status information
            if self.status_file.exists():
                with open(self.status_file, "r") as f:
                    json.load(f)  # Load status data for future use

            logger.info("API configuration loaded successfully")

        except Exception as e:
            logger.warning(f"Failed to load API configuration: {e}")

    def _save_configuration(self):
        """Save configuration to file."""
        try:
            # Ensure config directory exists
            self.config_file.parent.mkdir(parents=True, exist_ok=True)

            # Prepare configuration data
            config_data = {}
            for service_name, service in self.services.items():
                config_data[service_name] = {
                    "is_active": service.is_active,
                    "daily_usage": service.daily_usage,
                    "error_count": service.error_count,
                    "last_tested": (
                        service.last_tested.isoformat() if service.last_tested else None
                    ),
                }

            # Save configuration
            with open(self.config_file, "w") as f:
                json.dump(config_data, f, indent=2, default=str)

            logger.info("API configuration saved successfully")

        except Exception as e:
            logger.error(f"Failed to save API configuration: {e}")

    async def validate_all_services(
        self, fix_issues: bool = True
    ) -> Dict[str, APIKeyStatus]:
        """
        Validate all configured API services.

        Args:
            fix_issues: Whether to attempt automatic fixes for common issues

        Returns:
            Dictionary mapping service names to their status
        """
        service_statuses = {}

        try:
            logger.info("Starting comprehensive API service validation")

            # Test each service
            for service_name, service in self.services.items():
                try:
                    status = await self._validate_service(service)
                    service_statuses[service_name] = status

                    # Update service state based on validation
                    service.is_active = status.is_valid
                    service.last_tested = datetime.now()

                    if not status.is_valid and status.last_error:
                        service.error_count += 1

                        # Attempt fixes if requested
                        if fix_issues:
                            await self._attempt_service_fix(service, status.last_error)
                    else:
                        service.error_count = 0

                    # Log results
                    if status.is_valid:
                        logger.info(f"✅ {service_name}: Valid and active")
                    else:
                        logger.warning(f"❌ {service_name}: {status.last_error}")

                    # Rate limiting between tests
                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.error(f"Validation failed for {service_name}: {e}")
                    service_statuses[service_name] = APIKeyStatus(
                        service_name=service_name,
                        is_valid=False,
                        is_active=False,
                        quota_remaining=0,
                        rate_limit_reset=None,
                        last_error=str(e),
                        performance_score=0.0,
                        usage_today=0,
                    )

            # Save updated configuration
            self._save_configuration()

            # Generate summary report
            self._generate_validation_report(service_statuses)

            return service_statuses

        except Exception as e:
            logger.error(f"Service validation failed: {e}")
            return {}

    async def _validate_service(self, service: APIServiceConfig) -> APIKeyStatus:
        """Validate a specific API service."""
        try:
            # Get API key from environment or secrets manager
            api_key = await self._get_api_key(service)

            if not api_key:
                return APIKeyStatus(
                    service_name=service.service_name,
                    is_valid=False,
                    is_active=False,
                    quota_remaining=0,
                    rate_limit_reset=None,
                    last_error=f"No API key found for {service.api_key_env_var}",
                    performance_score=0.0,
                    usage_today=0,
                )

            # Construct test URL
            if not service.test_endpoint:
                return APIKeyStatus(
                    service_name=service.service_name,
                    is_valid=False,
                    is_active=False,
                    quota_remaining=0,
                    rate_limit_reset=None,
                    last_error="No test endpoint configured",
                    performance_score=0.0,
                    usage_today=0,
                )

            test_url = service.base_url + service.test_endpoint.format(api_key=api_key)

            # Prepare headers
            headers = {}
            for key, value in service.headers.items():
                headers[key] = value.format(api_key=api_key)

            # Make test request
            start_time = datetime.now()

            try:
                if service.auth_type == "basic_auth":
                    # For basic auth, use API key as username (common pattern)
                    auth = aiohttp.BasicAuth(api_key, "")
                    async with aiohttp.ClientSession(auth=auth) as session:
                        async with session.get(
                            test_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            response_data = await response.text()
                            status_code = response.status
                            response_headers = dict(response.headers)
                else:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            response_data = await response.text()
                            status_code = response.status
                            response_headers = dict(response.headers)

                response_time = (datetime.now() - start_time).total_seconds()

                # Analyze response
                is_valid = self._analyze_api_response(
                    service, status_code, response_data, response_headers
                )

                # Extract quota information
                quota_info = self._extract_quota_info(
                    service, response_headers, response_data
                )

                # Calculate performance score
                performance_score = self._calculate_performance_score(
                    response_time, status_code, is_valid
                )

                return APIKeyStatus(
                    service_name=service.service_name,
                    is_valid=is_valid,
                    is_active=is_valid,
                    quota_remaining=quota_info.get("remaining", service.daily_quota),
                    rate_limit_reset=quota_info.get("reset_time"),
                    last_error=(
                        None
                        if is_valid
                        else f"HTTP {status_code}: {response_data[:200]}"
                    ),
                    performance_score=performance_score,
                    usage_today=service.daily_usage,
                )

            except asyncio.TimeoutError:
                return APIKeyStatus(
                    service_name=service.service_name,
                    is_valid=False,
                    is_active=False,
                    quota_remaining=0,
                    rate_limit_reset=None,
                    last_error="Request timeout",
                    performance_score=0.0,
                    usage_today=service.daily_usage,
                )
            except aiohttp.ClientError as e:
                return APIKeyStatus(
                    service_name=service.service_name,
                    is_valid=False,
                    is_active=False,
                    quota_remaining=0,
                    rate_limit_reset=None,
                    last_error=f"Client error: {str(e)}",
                    performance_score=0.0,
                    usage_today=service.daily_usage,
                )

        except Exception as e:
            return APIKeyStatus(
                service_name=service.service_name,
                is_valid=False,
                is_active=False,
                quota_remaining=0,
                rate_limit_reset=None,
                last_error=f"Validation error: {str(e)}",
                performance_score=0.0,
                usage_today=service.daily_usage,
            )

    async def _get_api_key(self, service: APIServiceConfig) -> Optional[str]:
        """Get API key for service from environment or secrets manager."""
        try:
            # First try environment variable
            api_key = os.getenv(service.api_key_env_var)

            if api_key:
                return api_key

            # Try secrets manager with multiple key formats
            try:
                # Try the environment variable name format (e.g., openai_api_key)
                api_key = self.secrets_manager.get_secret(
                    service.api_key_env_var.lower()
                )
                if api_key:
                    return api_key

                # Try the setup script format (e.g., api_key_openai)
                # Map service names to the simple names used in setup script
                service_name_map = {
                    "OpenAI API": "openai",
                    "Google Custom Search": "google",
                    "Bing Web Search": "bing",
                    "Shodan": "shodan",
                    "VirusTotal": "virustotal",
                    "Have I Been Pwned": "hibp",
                    "Pipl": "pipl",
                    "Clearbit": "clearbit",
                    "Hunter.io": "hunterio",
                    "Spyse": "spyse",
                    "Censys": "censys",
                    "SecurityTrails": "securitytrails",
                    "WhoisXML API": "whoisxml",
                    "URLVoid": "urlvoid",
                    "IPInfo": "ipinfo",
                    "MaxMind GeoIP2": "maxmind",
                    "Twitter API v2": "twitter",
                    "Telegram Bot API": "telegram",
                }

                simple_name = service_name_map.get(service.service_name, service.service_name.lower().replace(" ", "").replace(".", ""))
                api_key = self.secrets_manager.get_secret(f"api_key_{simple_name}")
                if api_key:
                    return api_key

            except Exception as e:
                logger.debug(
                    f"Secrets manager lookup failed for {service.service_name}: {e}"
                )

            # Check for alternative environment variable names
            alt_names = [
                service.api_key_env_var.replace("_API_KEY", "_KEY"),
                service.api_key_env_var.replace("_KEY", "_TOKEN"),
                service.api_key_env_var.replace("API_", ""),
                service.service_name.upper().replace(" ", "_") + "_API_KEY",
            ]

            for alt_name in alt_names:
                api_key = os.getenv(alt_name)
                if api_key:
                    logger.info(
                        f"Found API key for {service.service_name} using alternative name: {alt_name}"
                    )
                    return api_key

            return None

        except Exception as e:
            logger.error(f"API key retrieval failed for {service.service_name}: {e}")
            return None

    def _analyze_api_response(
        self,
        service: APIServiceConfig,
        status_code: int,
        response_data: str,
        headers: Dict[str, str],
    ) -> bool:
        """Analyze API response to determine if service is working correctly."""
        try:
            # Success status codes
            if status_code in [200, 201, 202]:
                # Check for common error patterns in response body
                error_patterns = [
                    "error",
                    "invalid api key",
                    "unauthorized",
                    "forbidden",
                    "quota exceeded",
                    "rate limit",
                    "access denied",
                ]

                response_lower = response_data.lower()
                for pattern in error_patterns:
                    if pattern in response_lower:
                        logger.debug(
                            f"Error pattern '{pattern}' found in {service.service_name} response"
                        )
                        return False

                # Service-specific success validation
                if service.service_name == "Shodan":
                    return (
                        "query_credits" in response_data
                        or "scan_credits" in response_data
                    )
                elif service.service_name == "VirusTotal":
                    return (
                        "verbose_msg" in response_data
                        or "response_code" in response_data
                    )
                elif service.service_name == "Have I Been Pwned":
                    return status_code == 200  # HIBP returns 200 for valid requests
                elif service.service_name == "Twitter API v2":
                    return "data" in response_data or "id" in response_data

                return True

            elif status_code == 401:
                logger.debug(f"{service.service_name}: Unauthorized - invalid API key")
                return False
            elif status_code == 403:
                logger.debug(f"{service.service_name}: Forbidden - access denied")
                return False
            elif status_code == 429:
                logger.debug(f"{service.service_name}: Rate limited")
                return False  # Service exists but rate limited
            else:
                logger.debug(f"{service.service_name}: HTTP {status_code}")
                return False

        except Exception as e:
            logger.warning(f"Response analysis failed for {service.service_name}: {e}")
            return False

    def _extract_quota_info(
        self, service: APIServiceConfig, headers: Dict[str, str], response_data: str
    ) -> Dict[str, Any]:
        """Extract quota and rate limit information from API response."""
        quota_info: Dict[str, Any] = {}

        try:
            # Common rate limit headers
            rate_limit_headers = {
                "x-ratelimit-remaining": "remaining",
                "x-ratelimit-reset": "reset_time",
                "x-rate-limit-remaining": "remaining",
                "x-rate-limit-reset": "reset_time",
                "ratelimit-remaining": "remaining",
                "ratelimit-reset": "reset_time",
            }

            for header, key in rate_limit_headers.items():
                if header in headers:
                    value = headers[header]
                    if key == "remaining":
                        quota_info["remaining"] = int(value)
                    elif key == "reset_time":
                        # Handle different reset time formats
                        try:
                            if value.isdigit():
                                quota_info["reset_time"] = datetime.fromtimestamp(
                                    int(value)
                                )
                            else:
                                quota_info["reset_time"] = datetime.fromisoformat(
                                    value.replace("Z", "+00:00")
                                )
                        except (ValueError, TypeError):
                            pass

            # Service-specific quota extraction
            if service.service_name == "Shodan" and "query_credits" in response_data:
                try:
                    data = json.loads(response_data)
                    quota_info["remaining"] = data.get("query_credits", 0)
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass

            return quota_info

        except Exception as e:
            logger.warning(f"Quota extraction failed for {service.service_name}: {e}")
            return {}

    def _calculate_performance_score(
        self, response_time: float, status_code: int, is_valid: bool
    ) -> float:
        """Calculate performance score for API service."""
        try:
            if not is_valid:
                return 0.0

            # Base score for successful response
            base_score = 0.5

            # Response time scoring (lower is better)
            if response_time < 1.0:
                time_score = 0.4
            elif response_time < 3.0:
                time_score = 0.3
            elif response_time < 5.0:
                time_score = 0.2
            else:
                time_score = 0.1

            # Status code scoring
            if status_code == 200:
                status_score = 0.1
            else:
                status_score = 0.0

            return base_score + time_score + status_score

        except Exception as e:
            logger.warning(f"Performance score calculation failed: {e}")
            return 0.0

    async def _attempt_service_fix(self, service: APIServiceConfig, error: str):
        """Attempt to automatically fix common service issues."""
        try:
            logger.info(f"Attempting to fix {service.service_name}: {error}")

            # Common fixes based on error patterns
            if "invalid api key" in error.lower() or "unauthorized" in error.lower():
                # Check for API key in different formats/locations
                await self._check_alternative_api_keys(service)

            elif "rate limit" in error.lower() or "quota exceeded" in error.lower():
                # Reset usage counters and wait
                service.daily_usage = 0
                logger.info(f"Reset usage counter for {service.service_name}")
                await asyncio.sleep(60)  # Wait 1 minute

            elif "timeout" in error.lower():
                # Adjust timeout settings
                logger.info(
                    f"Consider adjusting timeout settings for {service.service_name}"
                )

            elif "forbidden" in error.lower():
                # Check service status and documentation
                logger.info(
                    f"Check API documentation for {service.service_name} - may need subscription upgrade"
                )

        except Exception as e:
            logger.warning(f"Auto-fix attempt failed for {service.service_name}: {e}")

    async def _check_alternative_api_keys(self, service: APIServiceConfig):
        """Check for API keys in alternative locations."""
        try:
            # Check config.ini file
            config_ini = Path("/workspaces/passive-osint-suite/config.ini")
            if config_ini.exists():
                import configparser

                config = configparser.ConfigParser()
                config.read(config_ini)

                # Look for API key in various sections
                sections_to_check = [
                    "api_keys",
                    "services",
                    service.service_name.lower(),
                ]
                keys_to_check = [
                    service.api_key_env_var.lower(),
                    service.service_name.lower().replace(" ", "_") + "_key",
                    "api_key",
                    "key",
                ]

                for section in sections_to_check:
                    if config.has_section(section):
                        for key in keys_to_check:
                            if config.has_option(section, key):
                                api_key = config.get(section, key)
                                if api_key:
                                    logger.info(
                                        f"Found alternative API key for {service.service_name} in config.ini"
                                    )
                                    os.environ[service.api_key_env_var] = api_key
                                    return

            # Check secrets.enc file
            try:
                decrypted_secrets = self.secrets_manager.get_all_secrets()
                for key, value in decrypted_secrets.items():
                    if (
                        service.service_name.lower() in key.lower()
                        or service.api_key_env_var.lower() in key.lower()
                    ):
                        logger.info(
                            f"Found alternative API key for {service.service_name} in secrets"
                        )
                        os.environ[service.api_key_env_var] = value
                        return
            except Exception as e:
                logger.debug(f"Secrets check failed: {e}")

        except Exception as e:
            logger.warning(
                f"Alternative API key check failed for {service.service_name}: {e}"
            )

    def _generate_validation_report(self, service_statuses: Dict[str, APIKeyStatus]):
        """Generate comprehensive validation report."""
        try:
            report_file = Path(
                "/workspaces/passive-osint-suite/logs/api_validation_report.txt"
            )
            report_file.parent.mkdir(parents=True, exist_ok=True)

            total_services = len(service_statuses)
            active_services = sum(
                1 for status in service_statuses.values() if status.is_valid
            )

            report = [
                "API Service Validation Report",
                "=" * 50,
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Total Services: {total_services}",
                f"Active Services: {active_services}",
                f"Success Rate: {(active_services/total_services)*100:.1f}%",
                "",
                "Service Details:",
                "-" * 20,
            ]

            # Group services by type
            service_types: Dict[str, List[APIKeyStatus]] = {}
            for status in service_statuses.values():
                service_type = self._get_service_type(status.service_name)
                if service_type not in service_types:
                    service_types[service_type] = []
                service_types[service_type].append(status)

            for service_type, statuses in service_types.items():
                report.append(f"\n{service_type.upper()}:")
                for status in statuses:
                    status_icon = "✅" if status.is_valid else "❌"
                    performance = (
                        f"({status.performance_score:.2f})" if status.is_valid else ""
                    )
                    quota = (
                        f"Quota: {status.quota_remaining}"
                        if status.quota_remaining > 0
                        else ""
                    )

                    report.append(
                        f"  {status_icon} {status.service_name} {performance} {quota}"
                    )
                    if status.last_error:
                        report.append(f"     Error: {status.last_error}")

            # Recommendations
            report.extend(["", "Recommendations:", "-" * 15])

            inactive_services = [s for s in service_statuses.values() if not s.is_valid]
            if inactive_services:
                report.append("• Configure API keys for inactive services:")
                for status in inactive_services:
                    env_var = self._get_env_var_for_service(status.service_name)
                    report.append(f"  - {status.service_name}: Set {env_var}")

            if active_services < total_services * 0.8:
                report.append(
                    "• Consider purchasing API subscriptions for better coverage"
                )

            report.append("• Regularly monitor rate limits and quotas")
            report.append("• Set up API key rotation for production use")

            # Write report
            with open(report_file, "w") as f:
                f.write("\n".join(report))

            logger.info(f"Validation report saved to {report_file}")

            # Also log summary to console
            logger.info(
                f"API Validation Summary: {active_services}/{total_services} services active ({(active_services/total_services)*100:.1f}%)"
            )

        except Exception as e:
            logger.error(f"Report generation failed: {e}")

    def _get_service_type(self, service_name: str) -> str:
        """Get service type for a service name."""
        for service in self.services.values():
            if service.service_name == service_name:
                return service.service_type
        return "unknown"

    def _get_env_var_for_service(self, service_name: str) -> str:
        """Get environment variable name for a service."""
        for service in self.services.values():
            if service.service_name == service_name:
                return service.api_key_env_var
        return "UNKNOWN_API_KEY"

    async def configure_service(
        self, service_name: str, api_key: str, save_to_secrets: bool = True
    ) -> bool:
        """Configure API key for a specific service."""
        try:
            if service_name not in self.services:
                logger.error(f"Unknown service: {service_name}")
                return False

            service = self.services[service_name]

            # Set environment variable
            os.environ[service.api_key_env_var] = api_key

            # Save to secrets manager if requested
            if save_to_secrets:
                self.secrets_manager.store_secret(
                    service.api_key_env_var.lower(), api_key
                )

            # Validate the new configuration
            status = await self._validate_service(service)

            if status.is_valid:
                service.is_active = True
                service.error_count = 0
                logger.info(f"Successfully configured {service_name}")
                self._save_configuration()
                return True
            else:
                logger.error(
                    f"Configuration failed for {service_name}: {status.last_error}"
                )
                return False

        except Exception as e:
            logger.error(f"Service configuration failed for {service_name}: {e}")
            return False

    def get_active_services(self, service_type: Optional[str] = None) -> List[str]:
        """Get list of active services, optionally filtered by type."""
        try:
            active_services = []

            for service_name, service in self.services.items():
                if service.is_active:
                    if service_type is None or service.service_type == service_type:
                        active_services.append(service_name)

            return active_services

        except Exception as e:
            logger.error(f"Failed to get active services: {e}")
            return []

    def get_service_config(self, service_name: str) -> Optional[APIServiceConfig]:
        """Get configuration for a specific service."""
        return self.services.get(service_name)

    async def optimize_performance(self):
        """Optimize API service performance based on usage patterns."""
        try:
            logger.info("Optimizing API service performance")

            # Analyze usage patterns
            high_usage_services = []
            low_performance_services = []

            for service_name, service in self.services.items():
                if service.is_active:
                    # Check for high usage
                    usage_ratio = service.daily_usage / service.daily_quota
                    if usage_ratio > 0.8:
                        high_usage_services.append(service_name)

                    # Validate and check performance
                    status = await self._validate_service(service)
                    if status.performance_score < 0.5:
                        low_performance_services.append(service_name)

            # Implement optimizations
            if high_usage_services:
                logger.info(f"High usage services detected: {high_usage_services}")
                # Could implement fallback switching or usage throttling

            if low_performance_services:
                logger.info(
                    f"Low performance services detected: {low_performance_services}"
                )
                # Could implement timeout adjustments or endpoint switching

            # Reset daily usage counters if it's a new day
            current_date = datetime.now().date()
            for service in self.services.values():
                if service.last_tested and service.last_tested.date() < current_date:
                    service.daily_usage = 0

            self._save_configuration()

        except Exception as e:
            logger.error(f"Performance optimization failed: {e}")


# Factory function
def create_api_config_manager() -> APIConfigurationManager:
    """Create and initialize API configuration manager."""
    return APIConfigurationManager()


# CLI interface for API management
async def main():
    """CLI interface for API configuration management."""
    import argparse

    parser = argparse.ArgumentParser(description="API Configuration Manager")
    parser.add_argument(
        "--validate", action="store_true", help="Validate all API services"
    )
    parser.add_argument(
        "--fix", action="store_true", help="Attempt to fix issues automatically"
    )
    parser.add_argument(
        "--configure",
        nargs=2,
        metavar=("SERVICE", "API_KEY"),
        help="Configure API key for service",
    )
    parser.add_argument("--list", action="store_true", help="List all services")
    parser.add_argument("--optimize", action="store_true", help="Optimize performance")

    args = parser.parse_args()

    manager = create_api_config_manager()

    if args.validate:
        print("Validating API services...")
        statuses = await manager.validate_all_services(fix_issues=args.fix)

        print(
            f"\nValidation complete: {sum(1 for s in statuses.values() if s.is_valid)}/{len(statuses)} services active"
        )

    elif args.configure:
        service_name, api_key = args.configure
        success = await manager.configure_service(service_name, api_key)
        print(
            f"Configuration {'successful' if success else 'failed'} for {service_name}"
        )

    elif args.list:
        print("Available API services:")
        for name, service in manager.services.items():
            status = "✅ Active" if service.is_active else "❌ Inactive"
            print(f"  {name} ({service.service_type}): {status}")

    elif args.optimize:
        print("Optimizing API performance...")
        await manager.optimize_performance()
        print("Optimization complete")

    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
