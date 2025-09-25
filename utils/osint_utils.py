"""
Utility functions for the OSINT Suite
"""

import asyncio
import configparser
import json
import logging
import time
from datetime import datetime
import importlib
from types import SimpleNamespace

# Optional third-party helpers: attempt imports and provide safe fallbacks to avoid
# linter/runtime errors when optional modules are not installed.
try:
    import validators  # preferred library for input validation
except Exception:
    # Minimal validators fallback if the 'validators' package is not available.
    import re

    class _ValidatorsFallback:
        _domain_re = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        _ipv4_re = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        _email_re = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
        _url_re = re.compile(r"^https?://\S+$")

        @staticmethod
        def domain(v):
            return bool(_ValidatorsFallback._domain_re.match(str(v)))

        @staticmethod
        def ipv4(v):
            return bool(_ValidatorsFallback._ipv4_re.match(str(v)))

        @staticmethod
        def ipv6(v):
            # Very lenient fallback for IPv6 (not exhaustive)
            return ":" in str(v)

        @staticmethod
        def email(v):
            return bool(_ValidatorsFallback._email_re.match(str(v)))

        @staticmethod
        def url(v):
            return bool(_ValidatorsFallback._url_re.match(str(v)))

    validators = _ValidatorsFallback()

# colorama fallback
try:
    # Use importlib to avoid static-import errors in some linters/environments
    colorama_mod = importlib.import_module("colorama")
    Fore = getattr(colorama_mod, "Fore")
    Style = getattr(colorama_mod, "Style")
    init = getattr(colorama_mod, "init")
    _colorama_available = True
except Exception:
    _colorama_available = False
    class _ColorFallback:
        CYAN = ""
    class _StyleFallback:
        RESET_ALL = ""
    Fore = _ColorFallback()
    Style = _StyleFallback()
    def init(autoreset: bool = False, convert: bool | None = None, strip: bool | None = None, wrap: bool = True) -> None:
        return None

# rich fallback (simple Table and Console implementations so UI code still works)
try:
    console_mod = importlib.import_module("rich.console")
    table_mod = importlib.import_module("rich.table")
    Console = getattr(console_mod, "Console")
    Table = getattr(table_mod, "Table")
    _rich_available = True
except Exception:
    _rich_available = False

    class Table:
        def __init__(self, title=""):
            self.title = title
            self._columns = []
            self._rows = []

        def add_column(self, name, style=None):
            self._columns.append(name)

        def add_row(self, *cells):
            self._rows.append([str(c) for c in cells])

        def __str__(self):
            if not self._columns and not self._rows:
                return self.title or ""
            col_widths = [len(c) for c in self._columns]
            for row in self._rows:
                for i, cell in enumerate(row):
                    if i >= len(col_widths):
                        col_widths.append(len(cell))
                    else:
                        col_widths[i] = max(col_widths[i], len(cell))
            sep = " | "
            header = sep.join(c.ljust(col_widths[i]) for i, c in enumerate(self._columns))
            lines = [f"{self.title}", header, "-" * len(header)]
            for row in self._rows:
                line = sep.join((row[i] if i < len(row) else "").ljust(col_widths[i]) for i in range(len(col_widths)))
                lines.append(line)
            return "\n".join(lines)

    class Console:
        def print(self, obj):
            # If it's a Table replacement, use its string representation
            try:
                print(str(obj))
            except Exception:
                print(obj)

# transport.sync_get is required by the module; import at runtime to avoid binding to
# a potentially incompatible type stub (which can declare NoReturn). Expose sync_get
# as a callable returning Any so static type checkers won't assert NoReturn.
from typing import Any, Callable
try:
    transport_mod = importlib.import_module("transport")
    # Assign the imported function directly (no variable annotation) so a later
    # fallback function definition does not get obscured by a prior annotated name.
    sync_get = getattr(transport_mod, "sync_get")
except Exception:
    # Minimal sync_get fallback that raises to make failures explicit at runtime
    def sync_get(*args, **kwargs) -> Any:
        raise RuntimeError("transport.sync_get is not available in this environment")

# Attempt to import optional integration modules; provide safe no-op fallbacks
# DoH client
try:
    doh_mod = importlib.import_module("utils.doh_client")
    resolve_dns = getattr(doh_mod, "resolve_dns")
    resolve_ip = getattr(doh_mod, "resolve_ip")
    resolve_ipv6 = getattr(doh_mod, "resolve_ipv6")
    DOH_AVAILABLE = True
except Exception:
    DOH_AVAILABLE = False
    logging.warning("DoH client not available - DNS resolution may be insecure")

    async def resolve_dns(domain, record_type='A'):
        # Return a simple namespace with .answers = []
        return SimpleNamespace(answers=[])

    async def resolve_ip(domain):
        return None

    async def resolve_ipv6(domain):
        return None

# Query obfuscation system
try:
    qo_mod = importlib.import_module("tools.query_obfuscation")
    obfuscated_batch = getattr(qo_mod, "obfuscated_batch")
    obfuscated_request = getattr(qo_mod, "obfuscated_request")
    query_obfuscator = getattr(qo_mod, "query_obfuscator")
    QueryPriority = getattr(qo_mod, "QueryPriority")
    OBFUSCATION_AVAILABLE = True
except Exception:
    OBFUSCATION_AVAILABLE = False
    logging.warning("Query obfuscation not available - operations may be detectable")

    async def obfuscated_request(url, proto, parameters, priority):
        return "mock-query-id"

    async def obfuscated_batch(queries):
        return "mock-batch-id"

    class _QueryObfuscatorFallback:
        @staticmethod
        async def start():
            return True

    class QueryPriority(int):
        def __new__(cls, value):
            return int.__new__(cls, value)

    query_obfuscator = _QueryObfuscatorFallback()

# Secrets manager
try:
    sm_mod = importlib.import_module("secrets_manager")
    get_api_key = getattr(sm_mod, "get_api_key")
    secrets_manager = getattr(sm_mod, "secrets_manager")
    store_api_key = getattr(sm_mod, "store_api_key")
    SECRETS_AVAILABLE = True
except Exception:
    SECRETS_AVAILABLE = False
    logging.warning("Secrets manager not available - API keys from config only")

    def get_api_key(service):
        return None

    class _SecretsManagerFallback:
        @staticmethod
        def list_secrets(service=None):
            return []

        @staticmethod
        def get_statistics():
            return {"available": False, "reason": "fallback"}

    secrets_manager = _SecretsManagerFallback()

    def store_api_key(service, api_key, **kwargs):
        return False

# Audit trail
try:
    audit_mod = importlib.import_module("audit_trail")
    audit_trail = getattr(audit_mod, "audit_trail")
    AUDIT_AVAILABLE = True
except Exception:
    AUDIT_AVAILABLE = False
    logging.warning("Audit trail not available - operations will not be logged")

    class _AuditFallback:
        @staticmethod
        def log_operation(**kwargs):
            # no-op
            return None

    audit_trail = _AuditFallback()

# OPSEC policy engine
try:
    opsec_mod = importlib.import_module("opsec_policy")
    enforce_policy = getattr(opsec_mod, "enforce_policy")
    OPSEC_AVAILABLE = True
except Exception:
    OPSEC_AVAILABLE = False
    logging.warning(
        "OPSEC policy engine not available - operations will not be policy-checked"
    )

    def enforce_policy(**kwargs):
        # Default allow-all policy
        return {"allowed": True, "warnings": [], "delays": [], "actions": []}

# Result encryption
try:
    re_mod = importlib.import_module("result_encryption")
    result_encryption = getattr(re_mod, "result_encryption")
    ENCRYPTION_AVAILABLE = True
except Exception:
    ENCRYPTION_AVAILABLE = False
    logging.warning("Result encryption not available - results stored in plaintext")

    class _ResultEncryptionFallback:
        @staticmethod
        def encrypt_result(**kwargs):
            # Fallback: return None to signal encryption not available
            return None

    result_encryption = _ResultEncryptionFallback()

# Initialize colorama and rich console
init(autoreset=True)
console = Console()


class OSINTUtils:
    def __init__(self, config_path="config/config.ini"):
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        self.setup_logging()

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get("SETTINGS", "LOG_LEVEL", fallback="INFO")
        # Strip quotes if present in config
        log_level = log_level.strip('"')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("logs/osint_suite.log"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)

    def get_api_key(self, service):
        """Get API key for a specific service using secure secrets manager"""
        # Try secure secrets manager first
        if SECRETS_AVAILABLE:
            api_key = get_api_key(service)
            if api_key:
                self.logger.debug(f"API key for {service} retrieved from secure store")
                return api_key
        
        # Fallback to config file
        try:
            # ConfigParser converts option names to lowercase, so we need to try both cases
            api_key = self.config.get("API_KEYS", service.lower())
            if api_key:
                self.logger.warning(
                    f"API key for {service} retrieved from config file - "
                    "consider moving to secure store"
                )
                return api_key
        except Exception:
            pass
        
        self.logger.error(f"No API key found for service: {service}")
        return None

    def get_all_api_keys(self):
        """Get all API keys from both secure store and config file"""
        all_keys = {}
        
        # Try to get all keys from secure secrets manager first
        if SECRETS_AVAILABLE:
            try:
                # Get all secrets from the manager
                secrets = secrets_manager.list_secrets()
                for secret in secrets:
                    if secret.get('service'):
                        api_key = get_api_key(secret['service'])
                        if api_key:
                            all_keys[secret['service']] = api_key
            except Exception as e:
                self.logger.warning(f"Failed to get API keys from secure store: {e}")
        
        # Fallback to config file for any missing keys
        if self.config.has_section("API_KEYS"):
            for option in self.config.options("API_KEYS"):
                if option not in all_keys:  # Don't override secure keys
                    try:
                        value = self.config.get("API_KEYS", option)
                        if value and value.strip():
                            # Convert lowercase option name back to uppercase for consistency
                            all_keys[option.upper()] = value
                    except Exception:
                        continue
        
        return all_keys

    def store_api_key_secure(self, service, api_key, description="", expires_days=None):
        """Store API key securely using secrets manager"""
        if not SECRETS_AVAILABLE:
            self.logger.error(
                "Secrets manager not available - cannot store API key securely"
            )
            return False
        
        success = store_api_key(
            service=service,
            api_key=api_key,
            description=description or f"API key for {service}",
            expires_days=expires_days
        )
        
        if success:
            self.logger.info(f"API key for {service} stored securely")
        else:
            self.logger.error(f"Failed to store API key for {service}")
        
        return success

    def list_stored_secrets(self, service=None):
        """List secrets stored in secure manager"""
        if not SECRETS_AVAILABLE:
            return []
        
        return secrets_manager.list_secrets(service)

    def get_secrets_status(self):
        """Get secrets manager status and statistics"""
        if not SECRETS_AVAILABLE:
            return {"available": False, "reason": "Secrets manager not imported"}
        
        try:
            stats = secrets_manager.get_statistics()
            stats["available"] = True
            return stats
        except Exception as e:
            return {"available": False, "error": str(e)}

    def validate_input(self, input_value, input_type):
        """Validate different types of input"""
        if input_type == "domain":
            return validators.domain(input_value)
        elif input_type == "ip":
            return validators.ipv4(input_value) or validators.ipv6(input_value)
        elif input_type == "email":
            return validators.email(input_value)
        elif input_type == "url":
            return validators.url(input_value)
        return True

    def make_request(self, url, headers=None, params=None, timeout=30, 
                     operation_type="http_request", actor="osint_utils"):
        """Make HTTP request with error handling using mandatory Tor proxy"""
        # Extract target from URL for policy enforcement
        from urllib.parse import urlparse
        target = urlparse(url).netloc or url
        
        # Enforce OPSEC policies
        if OPSEC_AVAILABLE:
            policy_result = enforce_policy(
                operation_type=operation_type,
                target=target,
                actor=actor,
                user_agent=headers.get('User-Agent') if headers else None
            )
            
            # Check if operation is allowed
            if not policy_result['allowed']:
                actions = ', '.join(policy_result['actions'])
                self.logger.error(f"HTTP request denied by OPSEC policy: {actions}")
                raise PermissionError(f"Request denied by OPSEC policy: {actions}")
            
            # Apply warnings
            for warning in policy_result['warnings']:
                self.logger.warning(f"OPSEC Policy Warning: {warning}")
            
            # Apply delays
            for delay in policy_result['delays']:
                self.logger.info(f"OPSEC Policy Delay: {delay} seconds")
                time.sleep(delay)
        
        # Log the request for audit
        if AUDIT_AVAILABLE:
            audit_trail.log_operation(
                operation="http_request",
                actor=actor,
                target=target,
                metadata={
                    "url": url, 
                    "timeout": timeout, 
                    "has_custom_headers": bool(headers),
                    "operation_type": operation_type
                }
            )
        
        try:
            default_headers = {
                "User-Agent": self.config.get(
                    "SETTINGS", "USER_AGENT", fallback="OSINT-Suite/1.0"
                )
            }
            if headers:
                default_headers.update(headers)

            response = sync_get(
                url, headers=default_headers, params=params, timeout=timeout
            )
            response.raise_for_status()
            return response
        except Exception as e:
            self.logger.error(f"Request failed: {e}")
            return None

    def make_obfuscated_request(
        self, 
        url, 
        headers=None, 
        params=None, 
        timeout=30, 
        priority=2,
        use_obfuscation=True
    ):
        """
        Make HTTP request with query obfuscation and anti-fingerprinting.
        
        Args:
            url: Target URL
            headers: Custom headers
            params: Query parameters
            timeout: Request timeout
            priority: Query priority (1=LOW, 2=NORMAL, 3=HIGH, 4=CRITICAL)
            use_obfuscation: Whether to use obfuscation (fallback to direct if False)
        
        Returns:
            Query ID for tracking (if obfuscated) or response object (if direct)
        """
        if not use_obfuscation or not OBFUSCATION_AVAILABLE:
            # Fallback to direct request
            return self.make_request(url, headers, params, timeout)
        
        try:
            default_headers = {
                "User-Agent": self.config.get(
                    "SETTINGS", "USER_AGENT", fallback="OSINT-Suite/1.0"
                )
            }
            if headers:
                default_headers.update(headers)
            
            parameters = {
                'headers': default_headers,
                'timeout': timeout
            }
            if params:
                parameters['params'] = params
            
            # Convert priority int to enum
            priority_enum = QueryPriority(priority)
            
            # Submit obfuscated request
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                query_id = loop.run_until_complete(
                    obfuscated_request(url, "http", parameters, priority_enum)
                )
                self.logger.info(f"Obfuscated request submitted: {query_id}")
                return query_id
            finally:
                loop.close()
                
        except Exception as e:
            self.logger.error(f"Obfuscated request failed: {e}")
            # Fallback to direct request
            return self.make_request(url, headers, params, timeout)

    def submit_batch_requests(
        self, 
        urls, 
        headers=None, 
        priority=2,
        add_decoys=True
    ):
        """
        Submit multiple requests as an obfuscated batch.
        
        Args:
            urls: List of URLs or (url, headers, params) tuples
            headers: Default headers for all requests
            priority: Batch priority
            add_decoys: Whether to add decoy requests
        
        Returns:
            Batch ID for tracking
        """
        if not OBFUSCATION_AVAILABLE:
            self.logger.warning("Obfuscation not available - using sequential requests")
            results = []
            for url_info in urls:
                if isinstance(url_info, str):
                    result = self.make_request(url_info, headers)
                else:
                    url, req_headers, params = url_info
                    combined_headers = headers.copy() if headers else {}
                    if req_headers:
                        combined_headers.update(req_headers)
                    result = self.make_request(url, combined_headers, params)
                results.append(result)
            return results
        
        try:
            default_headers = {
                "User-Agent": self.config.get(
                    "SETTINGS", "USER_AGENT", fallback="OSINT-Suite/1.0"
                )
            }
            if headers:
                default_headers.update(headers)
            
            # Prepare batch queries
            queries = []
            for url_info in urls:
                if isinstance(url_info, str):
                    url = url_info
                    req_headers = default_headers
                    params = {}
                else:
                    url, req_headers_extra, params = url_info
                    req_headers = default_headers.copy()
                    if req_headers_extra:
                        req_headers.update(req_headers_extra)
                    params = params or {}
                
                parameters = {
                    'headers': req_headers,
                    'params': params,
                    'timeout': 30
                }
                
                # Convert priority int to enum
                priority_enum = QueryPriority(priority)
                queries.append((url, "http", parameters, priority_enum))
            
            # Submit batch
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                batch_id = loop.run_until_complete(
                    obfuscated_batch(queries)
                )
                self.logger.info(f"Obfuscated batch submitted: {batch_id}")
                return batch_id
            finally:
                loop.close()
                
        except Exception as e:
            self.logger.error(f"Batch submission failed: {e}")
            return None

    def start_obfuscation_system(self):
        """Start the query obfuscation system."""
        if not OBFUSCATION_AVAILABLE:
            self.logger.warning("Query obfuscation not available")
            return False
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(query_obfuscator.start())
            self.logger.info("Query obfuscation system started")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start obfuscation system: {e}")
            return False

    def get_obfuscation_status(self):
        """Get current obfuscation system status and statistics."""
        if not OBFUSCATION_AVAILABLE:
            return {"available": False, "reason": "Obfuscation module not imported"}
        
        try:
            # Import the same module path used when the obfuscation subsystem is initialized.
            qo_module = importlib.import_module("tools.query_obfuscation")
            get_stats = getattr(qo_module, "get_obfuscation_stats", None)
            if get_stats is None:
                return {"available": False, "reason": "get_obfuscation_stats not implemented in tools.query_obfuscation"}
            stats = get_stats()
            if isinstance(stats, dict):
                stats["available"] = True
            else:
                stats = {"available": True, "stats": stats}
            return stats
        except Exception as e:
            self.logger.error(f"Failed to retrieve obfuscation status: {e}")
            return {"available": False, "error": str(e)}

    def save_results(self, data, filename, format="json"):
        """Save results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"output/{filename}_{timestamp}.{format}"

        try:
            if format == "json":
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2, default=str)
            elif format == "txt":
                with open(filepath, "w") as f:
                    if isinstance(data, dict):
                        for key, value in data.items():
                            f.write(f"{key}: {value}\n")
                    else:
                        f.write(str(data))

            self.logger.info(f"Results saved to: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return None
    
    def save_results_encrypted(self, data, operation, target, 
                             expires_in_hours=None, password=None, 
                             burn_after_read=False):
        """
        Save results using encryption.
        
        Args:
            data: Result data to encrypt
            operation: OSINT operation type
            target: Target of the operation
            expires_in_hours: Hours until expiration
            password: Optional password for encryption
            burn_after_read: Delete after first read
        
        Returns:
            Result ID if successful, None if failed
        """
        if not ENCRYPTION_AVAILABLE:
            self.logger.warning("Encryption not available - falling back to plain save")
            return self.save_results(data, f"{operation}_{target}")
        
        try:
            result_id = result_encryption.encrypt_result(
                result_data=data,
                operation=operation,
                target=target,
                expires_in_hours=expires_in_hours,
                password=password,
                burn_after_read=burn_after_read
            )
            
            self.logger.info(f"Results encrypted and saved: {result_id}")
            return result_id
            
        except Exception as e:
            self.logger.error(f"Failed to encrypt results: {e}")
            return None

    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ╔═══╗ ╔═══╗ ╔═══╗ ╔═╗ ╔╗ ╔═══╗     ╔═══╗ ╔╗ ╔╗ ╔═══╗ ╔═══╗ ║
║    ║ ╔═╝ ║ ╔═╝ ║ ╔═╝ ║ ║ ║║ ║ ╔═╝     ║ ╔═╝ ║║ ║║ ║ ╔═╝ ║ ╔═╝ ║
║    ║ ╚═╗ ║ ╚═╗ ║ ║   ║ ╚═╝║ ║ ╚═╗     ║ ╚═╗ ║║ ║║ ║ ║   ║ ╚═╗ ║
║    ║ ╔═╝ ║ ╔═╝ ║ ║   ║ ╔═╗║ ║ ╔═╝     ║ ╔═╝ ║║ ║║ ║ ║   ║ ╔═╝ ║
║    ║ ╚═╗ ║ ╚═╗ ║ ╚═╗ ║ ║ ║║ ║ ╚═╗     ║ ╚═╗ ║╚═╝║ ║ ╚═╗ ║ ╚═╗ ║
║    ╚═══╝ ╚═══╝ ╚═══╝ ╚═╝ ╚╝ ╚═══╝     ╚═══╝ ╚═══╝ ╚═══╝ ╚═══╝ ║
║                                                               ║
║    Passive Reconnaissance & Intelligence Gathering Suite      ║
║    Version 1.0 - Transnational Crime Investigation Focus     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
        """
        print(banner)

    def print_results_table(self, data, title="Results"):
        """Print results in a formatted table"""
        table = Table(title=title)

        if isinstance(data, dict) and data:
            # Add columns
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")

            # Add rows
            for key, value in data.items():
                if isinstance(value, (list, dict)):
                    value = json.dumps(value, indent=2)
                table.add_row(str(key), str(value))

        elif isinstance(data, list) and data:
            if isinstance(data[0], dict):
                # Get column names from first item
                columns = list(data[0].keys())
                for col in columns:
                    table.add_column(str(col), style="cyan")

                # Add data rows
                for item in data:
                    row = [str(item.get(col, "")) for col in columns]
                    table.add_row(*row)

        console.print(table)

    def validate_tor_connection(self):
        """Validate that Tor proxy is working"""
        from transport import sync_validate_tor_connection
        return sync_validate_tor_connection()

    def resolve_domain_secure(self, domain, record_type='A'):
        """
        Resolve domain using secure DoH through Tor.
        
        Args:
            domain: Domain name to resolve
            record_type: DNS record type (A, AAAA, MX, TXT, etc.)
        
        Returns:
            List of resolved records or None if resolution fails
        """
        # Log the DNS resolution for audit
        if AUDIT_AVAILABLE:
            audit_trail.log_operation(
                operation="dns_resolution",
                actor="osint_utils",
                target=domain,
                metadata={"record_type": record_type, "method": "doh"}
            )
        
        if not DOH_AVAILABLE:
            self.logger.warning("DoH client not available - falling back to system DNS")
            return None
        
        try:
            # Run async DoH resolution in a new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                response = loop.run_until_complete(resolve_dns(domain, record_type))
                
                if response.answers:
                    results = [answer.data for answer in response.answers]
                    self.logger.info(f"Resolved {domain} {record_type}: {results}")
                    return results
                else:
                    self.logger.warning(f"No {record_type} records found for {domain}")
                    return []
                    
            finally:
                loop.close()
                
        except Exception as e:
            self.logger.error(f"Secure DNS resolution failed for {domain}: {e}")
            return None

    def get_domain_ip_secure(self, domain):
        """Get IP address for domain using secure DoH."""
        if not DOH_AVAILABLE:
            return None
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                ip = loop.run_until_complete(resolve_ip(domain))
                if ip:
                    self.logger.info(f"Resolved {domain} to IP: {ip}")
                return ip
            finally:
                loop.close()
        except Exception as e:
            self.logger.error(f"Failed to resolve IP for {domain}: {e}")
            return None

    def get_domain_ipv6_secure(self, domain):
        """Get IPv6 address for domain using secure DoH."""
        if not DOH_AVAILABLE:
            return None
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                ipv6 = loop.run_until_complete(resolve_ipv6(domain))
                if ipv6:
                    self.logger.info(f"Resolved {domain} to IPv6: {ipv6}")
                return ipv6
            finally:
                loop.close()
        except Exception as e:
            self.logger.error(f"Failed to resolve IPv6 for {domain}: {e}")
            return None

    def rate_limit(self, delay=1):
        """Simple rate limiting"""
        time.sleep(delay)

    def clean_text(self, text):
        """Clean and normalize text"""
        if not text:
            return ""
        return " ".join(str(text).split())

    def extract_domains_from_text(self, text):
        """Extract domain names from text"""
        import re

        # Domain regex: match typical domain names (no stray spaces)
        domain_pattern = (
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        )
        return re.findall(domain_pattern, text)

    def extract_ips_from_text(self, text):
        """Extract IP addresses from text"""
        import re

        ip_pattern = (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )
        return re.findall(ip_pattern, text)

    def extract_emails_from_text(self, text):
        """Extract email addresses from text"""
        import re

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        return re.findall(email_pattern, text)
