"""Compatibility wrappers around the core transport helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional

from transport import (
    ProxiedTransport as _CoreProxiedTransport,
    Transport as _CoreTransport,
    get_tor_status as _get_tor_status,
    sync_get as _sync_get,
    transport as _shared_transport,
)

__all__ = [
    "Transport",
    "ProxiedTransport",
    "get_tor_status",
    "transport",
    "sync_get",
]


def get_tor_status() -> Dict[str, Any]:
    """Expose the core Tor status helper for legacy imports."""

    return _get_tor_status()


class ProxiedTransport(_CoreProxiedTransport):
    """Thin shim that defaults to the shared proxy-aware transport."""

    def __init__(
        self,
        proxy_url: str = "socks5h://127.0.0.1:9050",
        *,
        require_proxy: Optional[bool] = None,
        default_timeout: float = 15.0,
        min_interval: float = 1.0,
        retries: int = 3,
    ) -> None:
        super().__init__(
            proxy_url=proxy_url,
            require_proxy=require_proxy,
            default_timeout=default_timeout,
            min_interval=min_interval,
            retries=retries,
        )


class Transport(_CoreTransport):
    """Backwards-compatible facade over the shared transport implementation."""

    def __init__(
        self,
        proxy_url: Optional[str] = None,
        *,
        default_timeout: float = 15.0,
        min_interval: float = 1.0,
        retries: int = 3,
    ) -> None:
        super().__init__(
            proxy_url=proxy_url,
            default_timeout=default_timeout,
            min_interval=min_interval,
            retries=retries,
        )


# Provide legacy module-level handles
transport = _shared_transport
sync_get = _sync_get
