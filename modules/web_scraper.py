"""
Web Scraper Module - Enhanced with Safety Helpers

This module scrapes websites for keywords and content.
Enhanced in Phase 1 with safety wrappers for timeouts, retries, and validation.
"""

from typing import List, Optional

from src.passive_osint_common.safety import (
    safe_request,
    input_validation,
    handle_exceptions,
    configure_logger,
    is_non_empty_string,
)
from utils.osint_utils import OSINTUtils

# Configure module logger
logger = configure_logger(__name__)


class WebScraper(OSINTUtils):
    def __init__(self):
        super().__init__()
        logger.info("WebScraper module initialized")

    @input_validation(target=is_non_empty_string)
    @handle_exceptions(default_return={"status": "error", "data": []})
    def scrape(self, target: str, keywords: Optional[List[str]] = None):
        """
        Scrape a target website (news/blog/forum) for keywords.
        
        Args:
            target: URL or domain to scrape (e.g., "example.com" or "https://example.com")
            keywords: Optional list of keywords to search for
        
        Returns:
            Dictionary with status and matching lines/snippets
            
        Example:
            >>> scraper = WebScraper()
            >>> result = scraper.scrape("example.com", ["privacy", "security"])
            >>> print(f"Found {len(result['data'])} matches")
        """
        # Normalize URL - add https:// if missing
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        
        logger.info(f"Scraping {url} with keywords: {keywords}")
        
        # Use safe_request with timeout and retries
        resp = safe_request(
            url,
            timeout=30,  # Increased from 15 for reliability
            max_retries=3,
            rate_limit_delay=0.5
        )
        
        if not resp or not resp.ok:
            logger.error(f"Failed to scrape {url}")
            return {
                "status": "error",
                "error": f"HTTP {resp.status_code if resp else 'No response'}",
                "data": []
            }
        
        text = resp.text
        results = []
        
        if keywords:
            # Search for keywords in content
            logger.debug(f"Searching for {len(keywords)} keywords")
            
            for kw in keywords:
                kw_lower = kw.lower()
                matches = 0
                
                for line in text.splitlines():
                    if kw_lower in line.lower():
                        # Trim and clean the line
                        cleaned_line = line.strip()
                        if cleaned_line and len(cleaned_line) > 10:  # Skip very short lines
                            results.append({
                                "keyword": kw,
                                "line": cleaned_line[:500],  # Limit line length
                                "match": True
                            })
                            matches += 1
                
                logger.debug(f"Found {matches} matches for keyword '{kw}'")
        else:
            # No keywords - return first 20 lines
            logger.debug("No keywords provided, returning first 20 lines")
            
            lines = text.splitlines()
            for line in lines[:20]:
                cleaned_line = line.strip()
                if cleaned_line:  # Skip empty lines
                    results.append({
                        "line": cleaned_line[:500],  # Limit line length
                        "match": False
                    })
        
        logger.info(f"Scraping complete: {len(results)} results from {url}")
        return {
            "status": "success",
            "data": results,
            "count": len(results),
            "url": url,
            "keywords": keywords or []
        }
