"""
Wayback Machine Module - Enhanced with Safety Helpers

This module retrieves historical snapshots from archive.org Wayback Machine.
Enhanced in Phase 1 with safety wrappers for timeouts, retries, and validation.
"""

from src.passive_osint_common.safety import (
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    is_valid_url,
)
from utils.osint_utils import OSINTUtils

# Configure module logger
logger = configure_logger(__name__)


class WaybackMachine(OSINTUtils):
    def __init__(self):
        super().__init__()
        logger.info("WaybackMachine module initialized")

    @input_validation(url=is_valid_url)
    @handle_exceptions(default_return={"status": "error", "snapshots": []})
    def fetch_snapshots(self, url: str, limit: int = None):
        """
        Fetch historical snapshots for a URL from archive.org Wayback Machine.

        Args:
            url: Valid URL to lookup in Wayback Machine
            limit: Optional limit on number of snapshots to return

        Returns:
            Dictionary with status and list of snapshots

        Example:
            >>> wm = WaybackMachine()
            >>> result = wm.fetch_snapshots("https://example.com")
            >>> print(f"Found {len(result['snapshots'])} snapshots")
        """
        logger.info(f"Fetching Wayback Machine snapshots for: {url}")

        # Build API URL with proper parameters
        api_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={url}&output=json&fl=timestamp,original&collapse=digest"
        )

        # Use safe_request with timeout and retries
        resp = safe_request(
            api_url,
            timeout=30,
            max_retries=3,
            rate_limit_delay=0.5,  # Be respectful to archive.org
        )

        if not resp or not resp.ok:
            logger.error(f"Failed to fetch snapshots for {url}")
            return {
                "status": "error",
                "error": f"HTTP {resp.status_code if resp else 'No response'}",
                "snapshots": [],
            }

        try:
            data = resp.json()

            # Skip header row (first entry)
            if len(data) <= 1:
                logger.warning(f"No snapshots found for {url}")
                return {"status": "success", "snapshots": [], "count": 0}

            snapshots = []
            entries = data[1:]  # Skip header

            # Apply limit if specified
            if limit:
                entries = entries[:limit]

            logger.debug(f"Processing {len(entries)} snapshot entries")

            for entry in entries:
                if len(entry) >= 2:
                    timestamp, original = entry[0], entry[1]
                    snapshots.append(
                        {
                            "timestamp": timestamp,
                            "snapshot_url": f"https://web.archive.org/web/{timestamp}/{original}",
                            "original_url": original,
                        }
                    )

            logger.info(f"Retrieved {len(snapshots)} snapshots for {url}")
            return {
                "status": "success",
                "snapshots": snapshots,
                "count": len(snapshots),
                "url": url,
            }

        except (ValueError, KeyError) as e:
            logger.error(f"Failed to parse Wayback Machine response: {e}")
            return {
                "status": "error",
                "error": f"Failed to parse response: {e}",
                "snapshots": [],
            }
