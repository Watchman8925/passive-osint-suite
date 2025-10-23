"""Tests for the proxy-aware transport helpers."""

from __future__ import annotations

import pytest

import transport


class _DummyConnection:
    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        return None


def test_proxied_transport_falls_back_without_tor(monkeypatch):
    """When Tor is unavailable we should fall back to direct requests."""

    def _raise_os_error(*args, **kwargs):
        raise OSError("unreachable")

    monkeypatch.setenv("OSINT_REQUIRE_TOR", "false")
    monkeypatch.setattr(transport.socket, "create_connection", _raise_os_error)

    proxied = transport.ProxiedTransport(require_proxy=False)

    assert proxied.using_proxy is False
    assert proxied.session.proxies == {}


def test_proxied_transport_can_require_tor(monkeypatch):
    """If Tor is marked as required we should raise a clear error."""

    def _raise_os_error(*args, **kwargs):
        raise OSError("still unreachable")

    monkeypatch.setenv("OSINT_REQUIRE_TOR", "true")
    monkeypatch.setattr(transport.socket, "create_connection", _raise_os_error)

    with pytest.raises(RuntimeError, match="Tor proxy is required"):
        transport.ProxiedTransport()


def test_proxied_transport_detects_available_proxy(monkeypatch):
    """When the proxy port is reachable we continue to use it."""

    monkeypatch.setenv("OSINT_REQUIRE_TOR", "false")
    monkeypatch.setattr(
        transport.socket,
        "create_connection",
        lambda *args, **kwargs: _DummyConnection(),
    )

    proxied = transport.ProxiedTransport()

    assert proxied.using_proxy is True
    assert proxied.session.proxies["http"].startswith("socks5h://")
