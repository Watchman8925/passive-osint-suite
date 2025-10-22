from __future__ import annotations

from modules.domain_recon import DomainRecon


class _DummyResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        self.text = ""

    def json(self):
        return self._payload


def test_subdomain_lookups_are_cached(monkeypatch):
    recon = DomainRecon()
    call_count = {"count": 0}

    def fake_request(url, *args, **kwargs):
        call_count["count"] += 1
        if "crt.sh" in url:
            return _DummyResponse([{"name_value": "a.example.com\nwww.example.com"}])
        if "securitytrails" in url:
            return _DummyResponse({"subdomains": ["api", "cdn"]})
        return _DummyResponse({"subdomains": ["logs.example.com"]})

    monkeypatch.setattr(recon, "make_request", fake_request)
    monkeypatch.setattr(recon, "get_api_key", lambda key: "token")

    first = recon.find_subdomains("example.com")
    second = recon.find_subdomains("example.com")

    assert sorted(first) == sorted(second)
    # Only the first pass should hit the network helpers (3 sources)
    assert call_count["count"] == 3


def test_dns_resolver_uses_short_timeout():
    recon = DomainRecon()
    assert recon._resolver.lifetime == recon._DNS_TIMEOUT_SECONDS
