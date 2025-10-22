from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from utils.osint_utils import OSINTUtils


class SocialMediaFootprint(OSINTUtils):
    """Lightweight scraper that verifies platform markers before reporting hits."""

    _PLATFORM_MARKERS = {
        "Twitter": {
            "positive": (
                re.compile(r'property="og:type"\s+content="profile"', re.IGNORECASE),
                re.compile(r'"followers_count"\s*:\s*\d+', re.IGNORECASE),
            ),
            "negative": (
                re.compile(r'"error"\s*:\s*"NotFound"', re.IGNORECASE),
                re.compile(r"account suspended", re.IGNORECASE),
                re.compile(r"sign in to x", re.IGNORECASE),
            ),
        },
        "Reddit": {
            "positive": (
                re.compile(r'property="og:type"\s+content="profile"', re.IGNORECASE),
                re.compile(r'"subreddit":"u_\w+"', re.IGNORECASE),
            ),
            "negative": (
                re.compile(r"this community is private", re.IGNORECASE),
                re.compile(r"page not found", re.IGNORECASE),
            ),
        },
    }

    def __init__(self) -> None:
        super().__init__()

    def scrape_profiles(self, name_or_handle: str) -> Dict[str, Any]:
        """Return verified public profile URLs for the provided handle."""

        profiles: List[Dict[str, str]] = []
        errors: List[Dict[str, str]] = []

        checks = (
            (
                "Twitter",
                f"https://twitter.com/{name_or_handle}",
                {},
            ),
            (
                "Reddit",
                f"https://www.reddit.com/user/{name_or_handle}",
                {"User-Agent": "Mozilla/5.0"},
            ),
        )

        for platform, url, headers in checks:
            result = self._fetch_profile(platform, url, headers or None)
            if result and "url" in result:
                profiles.append(result)
            elif result and "error" in result:
                errors.append({"platform": platform, "error": result["error"]})

        return {"status": "success", "profiles": profiles, "errors": errors}

    def _fetch_profile(
        self, platform: str, url: str, headers: Optional[Dict[str, str]]
    ) -> Optional[Dict[str, str]]:
        """Fetch and validate a single platform profile."""

        try:
            response = self.request_with_fallback(
                "get", url, timeout=15, headers=headers, allow_fallback=True
            )
        except Exception as exc:  # pragma: no cover - network errors vary
            return {"error": str(exc)}

        if response.status_code == 404:
            return None

        if response.status_code >= 400:
            return {"error": f"HTTP {response.status_code}"}

        body = response.text or ""
        markers = self._PLATFORM_MARKERS.get(platform)
        if not markers:
            return None

        if any(pattern.search(body) for pattern in markers["negative"]):
            return None

        if any(pattern.search(body) for pattern in markers["positive"]):
            return {"platform": platform, "url": url}

        return {"error": "Profile markers not detected"}
