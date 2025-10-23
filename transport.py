"""Transport helpers with rate limiting, retries, and Tor fallbacks."""

from __future__ import annotations

import os
import socket
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class _RateLimiter:
    """Simple per-host rate limiter to avoid overwhelming public APIs."""

    def __init__(self, min_interval: float = 1.0) -> None:
        self._min_interval = float(min_interval)
        self._lock = threading.Lock()
        self._last_seen: Dict[str, float] = {}

    def wait(self, host: str) -> None:
        """Block until it is safe to issue the next request for ``host``."""

        if self._min_interval <= 0:
            return

        # Use a simple retry loop so we do not hold the lock while sleeping.
        while True:
            wait_for: float = 0.0
            now = time.monotonic()
            with self._lock:
                last = self._last_seen.get(host)
                if last is not None:
                    elapsed = now - last
                    remaining = self._min_interval - elapsed
                    if remaining > 0:
                        wait_for = remaining
                    else:
                        self._last_seen[host] = now
                        return
                else:
                    self._last_seen[host] = now
                    return

            if wait_for > 0:
                time.sleep(wait_for)


def get_tor_status() -> Dict[str, Any]:
    """Get Tor network status"""
    try:
        # Try to connect to Tor control port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", 9051))
        sock.close()

        if result == 0:
            # Tor control port is open, try to get status
            try:
                import stem  # noqa: F401
                from stem import Signal  # noqa: F401
                from stem.control import Controller

                with Controller.from_port(port=9051) as controller:
                    controller.authenticate()
                    circuits = list(controller.get_circuits())
                    return {
                        "active": True,
                        "circuits": len(circuits),
                        "bridges": [],  # Would need more complex stem queries
                        "exit_nodes": len([c for c in circuits if c.status == "BUILT"]),
                    }
            except ImportError:
                # stem not available, but Tor seems to be running
                return {"active": True, "circuits": [], "bridges": [], "exit_nodes": []}
            except Exception:
                # Tor is running but we can't query it
                return {"active": True, "circuits": [], "bridges": [], "exit_nodes": []}
        else:
            return {"active": False, "circuits": [], "bridges": [], "exit_nodes": []}
    except Exception:
        return {"active": False, "circuits": [], "bridges": [], "exit_nodes": []}


class Transport:
    """Main transport class for requests."""

    def __init__(
        self,
        proxy_url: Optional[str] = None,
        *,
        default_timeout: float = 15.0,
        min_interval: float = 1.0,
        retries: int = 3,
    ) -> None:
        self.default_timeout = float(default_timeout)
        self._rate_limiter = _RateLimiter(min_interval=min_interval)
        self.proxy_url = proxy_url

        session = requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if proxy_url:
            session.proxies = {"http": proxy_url, "https": proxy_url}

        self.transport: requests.Session = session

    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform a rate-limited ``GET`` request with a sane timeout."""

        timeout = kwargs.pop("timeout", self.default_timeout)
        host = urlparse(url).netloc or url
        self._rate_limiter.wait(host)
        return self.transport.get(url, timeout=timeout, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Perform a rate-limited ``POST`` request with a sane timeout."""

        timeout = kwargs.pop("timeout", self.default_timeout)
        host = urlparse(url).netloc or url
        self._rate_limiter.wait(host)
        return self.transport.post(url, timeout=timeout, **kwargs)


class ProxiedTransport:
    """Backward-compatible proxy transport wrapper."""

    def __init__(
        self,
        proxy_url: str = "socks5h://127.0.0.1:9050",
        *,
        require_proxy: Optional[bool] = None,
        default_timeout: float = 15.0,
        min_interval: float = 1.0,
        retries: int = 3,
    ) -> None:
        self.proxy_url = proxy_url
        self._require_proxy = self._should_require_proxy(require_proxy)
        self._proxy_available = self._is_proxy_available(proxy_url)

        if not self._proxy_available and self._require_proxy:
            raise RuntimeError(
                "Tor proxy is required but not available. Set OSINT_REQUIRE_TOR=false to allow direct connections."
            )

        effective_proxy = proxy_url if self._proxy_available else None
        self._inner = Transport(
            proxy_url=effective_proxy,
            default_timeout=default_timeout,
            min_interval=min_interval,
            retries=retries,
        )
        self.session = self._inner.transport

    def get(self, url: str, **kwargs) -> requests.Response:
        return self._inner.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self._inner.post(url, **kwargs)

    @property
    def using_proxy(self) -> bool:
        """Return ``True`` when requests are routed through the proxy."""

        return self._inner.proxy_url is not None

    @staticmethod
    def _should_require_proxy(require_proxy: Optional[bool]) -> bool:
        if require_proxy is not None:
            return require_proxy
        return os.getenv("OSINT_REQUIRE_TOR", "false").lower() in {
            "1",
            "true",
            "yes",
        }

    @staticmethod
    def _is_proxy_available(proxy_url: str) -> bool:
        parsed = urlparse(proxy_url)
        if not parsed.hostname or not parsed.port:
            return False

        try:
            with socket.create_connection((parsed.hostname, parsed.port), timeout=1.0):
                return True
        except OSError:
            return False


# Global transport instance with Tor proxy for anonymity
_transport = ProxiedTransport()

# Export transport instance for DoH client compatibility
transport = _transport


def sync_get(url: str, **kwargs) -> requests.Response:
    """Synchronous GET request using the global transport"""
    return _transport.get(url, **kwargs)


def sync_validate_tor_connection() -> bool:
    """Validate that Tor proxy connection is working"""
    try:
        # Try to make a request through Tor to a known .onion service or check
        # This is a simple check - in production you'd want more robust validation
        test_url = "https://check.torproject.org/api/ip"
        response = sync_get(test_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("IsTor", False)
        return False
    except Exception:
        return False
