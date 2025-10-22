from __future__ import annotations

from modules.social_media_footprint import SocialMediaFootprint


class DummyResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def test_scrape_profiles_requires_markers(monkeypatch):
    footprint = SocialMediaFootprint()
    responses = [
        DummyResponse(200, '<meta property="og:type" content="profile">'),
        DummyResponse(200, "<html><title>Profile</title></html>"),
    ]

    def fake_request(method, url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(footprint, "request_with_fallback", fake_request)
    result = footprint.scrape_profiles("alice")

    assert {profile["platform"] for profile in result["profiles"]} == {"Twitter"}
    assert result["errors"][0]["platform"] == "Reddit"
    assert "markers" in result["errors"][0]["error"].lower()


def test_scrape_profiles_handles_http_errors(monkeypatch):
    footprint = SocialMediaFootprint()
    responses = [DummyResponse(403, ""), DummyResponse(404, "")]

    def fake_request(method, url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(footprint, "request_with_fallback", fake_request)
    result = footprint.scrape_profiles("bob")

    assert result["profiles"] == []
    assert result["errors"][0] == {"platform": "Twitter", "error": "HTTP 403"}
    # Reddit 404 should be treated as not found without error entry
    assert len(result["errors"]) == 1
