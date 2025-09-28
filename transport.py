"""
Transport utilities for OSINT Suite
Tor proxy and network transport management
"""

import requests
from typing import Any, Dict, Optional, Union

def get_tor_status() -> Dict[str, Any]:
    """Get Tor network status"""
    try:
        # Try to connect to Tor control port
        import socket

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


class ProxiedTransport:
    """Proxied transport for requests"""

    def __init__(self, proxy_url: str = "socks5h://127.0.0.1:9050"):
        self.proxy_url = proxy_url
        self.session = requests.Session()
        self.session.proxies = {"http": proxy_url, "https": proxy_url}

    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request through proxy"""
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request through proxy"""
        return self.session.post(url, **kwargs)


class Transport:
    """Main transport class for requests"""

    def __init__(self, proxy_url: Optional[str] = None):
        if proxy_url:
            self.transport: Union[ProxiedTransport, requests.Session] = ProxiedTransport(proxy_url)
        else:
            self.transport = requests.Session()

    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request"""
        if isinstance(self.transport, ProxiedTransport):
            return self.transport.get(url, **kwargs)
        else:
            return self.transport.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request"""
        if isinstance(self.transport, ProxiedTransport):
            return self.transport.post(url, **kwargs)
        else:
            return self.transport.post(url, **kwargs)


# Global transport instance
_transport = Transport()


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
