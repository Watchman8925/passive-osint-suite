"""
WHOIS History Module - Enhanced with Safety Helpers

This module retrieves WHOIS history for domains using public sources.
Enhanced in Phase 1 with safety wrappers for timeouts, retries, and validation.
"""

from bs4 import BeautifulSoup

from src.passive_osint_common.safety import (
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    is_valid_domain,
)
from utils.osint_utils import OSINTUtils

# Configure module logger
logger = configure_logger(__name__)


class WhoisHistory(OSINTUtils):
    def __init__(self):
        super().__init__()
        logger.info("WhoisHistory module initialized")

    @input_validation(domain=is_valid_domain)
    @handle_exceptions(default_return={"status": "error", "history": []})
    def get_history(self, domain: str):
        """
        Scrape public WHOIS history from viewdns.info (no login, OPSEC safe).
        
        Args:
            domain: Valid domain name to lookup
        
        Returns:
            Dictionary with status and history list
            
        Example:
            >>> wh = WhoisHistory()
            >>> result = wh.get_history("example.com")
            >>> print(result["status"])
            success
        """
        logger.info(f"Retrieving WHOIS history for: {domain}")
        
        url = f"https://viewdns.info/iphistory/?domain={domain}"
        
        # Use safe_request with timeout and retries
        resp = safe_request(
            url,
            timeout=30,  # Increased from 20 for reliability
            max_retries=3,
            rate_limit_delay=0.5  # Be respectful to viewdns.info
        )
        
        if not resp or not resp.ok:
            logger.error(f"Failed to retrieve WHOIS history for {domain}")
            return {
                "status": "error",
                "error": f"HTTP {resp.status_code if resp else 'No response'}",
                "history": []
            }
        
        # Parse HTML response
        soup = BeautifulSoup(resp.text, "html.parser")
        history = []
        table = soup.find("table", {"border": "1"})
        
        if table:
            rows = table.find_all("tr")[1:]  # Skip header row
            logger.debug(f"Found {len(rows)} history entries")
            
            for row in rows:
                cols = row.find_all("td")
                if len(cols) >= 2:
                    history.append({
                        "ip": cols[0].text.strip(),
                        "date": cols[1].text.strip(),
                    })
        else:
            logger.warning(f"No history table found for {domain}")
        
        logger.info(f"Retrieved {len(history)} WHOIS history entries for {domain}")
        return {"status": "success", "history": history, "count": len(history)}
