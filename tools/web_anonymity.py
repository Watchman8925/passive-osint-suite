"""
Web Anonymity Module
===================

Provides anonymous web request functionality for OSINT operations.
This is a stub implementation that uses regular requests for passive operations.
"""

import asyncio
import logging
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class AnonymousSession:
    """Session with retry logic for anonymous requests."""

    def __init__(self):
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3, status_forcelist=[429, 500, 502, 503, 504], backoff_factor=1
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set a reasonable user agent
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )

    async def get(self, url: str, **kwargs) -> requests.Response:
        """Make an anonymous GET request."""

        def _sync_get():
            try:
                response = self.session.get(url, timeout=30, **kwargs)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.warning(f"Request failed for {url}: {e}")
                raise

        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_get)


# Global session instance
_anonymous_session = AnonymousSession()


async def ensure_anonymous_request(url: str, **kwargs) -> Optional[requests.Response]:
    """
    Make an anonymous web request.

    This is a stub implementation that uses regular requests.
    For true anonymity, this should be enhanced with Tor, proxies, etc.

    Args:
        url: The URL to request
        **kwargs: Additional arguments for the request

    Returns:
        Response object or None if failed
    """
    try:
        return await _anonymous_session.get(url, **kwargs)
    except Exception as e:
        logger.error(f"Anonymous request failed for {url}: {e}")
        return None
