"""
Web Discovery and Content Analysis Module
Provides advanced web crawling and content discovery using open source tools
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import tempfile
import shutil
import re
import urllib.parse

logger = logging.getLogger(__name__)

class WebDiscoveryEngine:
    """Web discovery engine using open source tools"""

    def __init__(self):
        self.tools = {
            'httpx': self._check_tool('httpx'),
            'gau': self._check_tool('gau'),
            'waybackurls': self._check_tool('waybackurls'),
            'gospider': self._check_tool('gospider'),
            'hakrawler': self._check_tool('hakrawler'),
            'katana': self._check_tool('katana')
        }

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            subprocess.run([tool_name, '--help' if tool_name not in ['gau', 'waybackurls', 'gospider'] else '-h'],
                         capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def discover_urls_from_wayback(self, domain: str, include_subs: bool = True) -> Dict[str, Any]:
        """
        Discover URLs from Wayback Machine using Gau

        Args:
            domain: Target domain
            include_subs: Include subdomains

        Returns:
            Dictionary containing discovered URLs
        """
        if not self.tools['gau']:
            return {"error": "Gau not available"}

        try:
            cmd = ['gau', domain]
            if include_subs:
                cmd.append('--subs')

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            urls = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                urls = [line.strip() for line in lines if line.strip()]

            # Categorize URLs
            url_categories = self._categorize_urls(urls)

            return {
                "success": True,
                "domain": domain,
                "total_urls": len(urls),
                "urls": urls[:1000],  # Limit for performance
                "categories": url_categories
            }

        except subprocess.TimeoutExpired:
            return {"error": "Wayback URL discovery timeout"}

    def extract_urls_from_wayback(self, domain: str) -> Dict[str, Any]:
        """
        Extract URLs from Wayback Machine using Waybackurls

        Args:
            domain: Target domain

        Returns:
            Dictionary containing extracted URLs
        """
        if not self.tools['waybackurls']:
            return {"error": "Waybackurls not available"}

        try:
            result = subprocess.run(
                ['waybackurls', domain],
                capture_output=True,
                text=True,
                timeout=120
            )

            urls = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                urls = [line.strip() for line in lines if line.strip()]

            # Remove duplicates and categorize
            unique_urls = list(set(urls))
            url_categories = self._categorize_urls(unique_urls)

            return {
                "success": True,
                "domain": domain,
                "total_urls": len(unique_urls),
                "urls": unique_urls[:1000],  # Limit for performance
                "categories": url_categories
            }

        except subprocess.TimeoutExpired:
            return {"error": "Wayback URL extraction timeout"}

    def crawl_website(self, url: str, depth: int = 2) -> Dict[str, Any]:
        """
        Crawl website using Gospider

        Args:
            url: Target URL to crawl
            depth: Crawling depth

        Returns:
            Dictionary containing crawling results
        """
        if not self.tools['gospider']:
            return {"error": "Gospider not available"}

        try:
            cmd = ['gospider', '-s', url, '-d', str(depth), '-t', '10', '-c', '5', '--json']

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            findings = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            # Extract URLs from findings
            urls = []
            for finding in findings:
                if 'output' in finding:
                    urls.append(finding['output'])

            url_categories = self._categorize_urls(urls)

            return {
                "success": True,
                "target_url": url,
                "depth": depth,
                "total_findings": len(findings),
                "urls_discovered": len(urls),
                "urls": urls[:500],  # Limit for performance
                "categories": url_categories,
                "raw_findings": findings[:100]  # Sample findings
            }

        except subprocess.TimeoutExpired:
            return {"error": "Website crawling timeout"}

    def probe_http_endpoints(self, urls: List[str]) -> Dict[str, Any]:
        """
        Probe HTTP endpoints using Httpx

        Args:
            urls: List of URLs to probe

        Returns:
            Dictionary containing probe results
        """
        if not self.tools['httpx']:
            return {"error": "Httpx not available"}

        if not urls:
            return {"error": "No URLs provided"}

        try:
            # Write URLs to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for url in urls:
                    f.write(url + '\n')
                url_file = f.name

            result = subprocess.run(
                ['httpx', '-l', url_file, '-json', '-threads', '10', '-timeout', '10'],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Clean up temp file
            os.unlink(url_file)

            results = []
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            probe_result = json.loads(line)
                            results.append(probe_result)
                        except json.JSONDecodeError:
                            continue

            # Summarize results
            summary = {
                "total_probed": len(urls),
                "successful": len([r for r in results if r.get('status_code', 0) < 400]),
                "redirects": len([r for r in results if 300 <= r.get('status_code', 0) < 400]),
                "client_errors": len([r for r in results if 400 <= r.get('status_code', 0) < 500]),
                "server_errors": len([r for r in results if r.get('status_code', 0) >= 500])
            }

            return {
                "success": True,
                "summary": summary,
                "results": results[:200],  # Limit for performance
                "raw_output": result.stdout[:5000] if len(result.stdout) > 5000 else result.stdout
            }

        except subprocess.TimeoutExpired:
            return {"error": "HTTP endpoint probing timeout"}

    def _categorize_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        Categorize URLs by type

        Args:
            urls: List of URLs to categorize

        Returns:
            Dictionary with categorized URLs
        """
        categories = {
            "javascript": [],
            "css": [],
            "images": [],
            "documents": [],
            "api_endpoints": [],
            "forms": [],
            "other": []
        }

        for url in urls:
            parsed = urllib.parse.urlparse(url.lower())

            # Check file extensions
            path = parsed.path
            if any(ext in path for ext in ['.js', '.jsx', '.ts', '.tsx']):
                categories["javascript"].append(url)
            elif any(ext in path for ext in ['.css', '.scss', '.sass']):
                categories["css"].append(url)
            elif any(ext in path for ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp']):
                categories["images"].append(url)
            elif any(ext in path for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']):
                categories["documents"].append(url)
            elif any(pattern in path for pattern in ['/api/', '/v1/', '/v2/', '/graphql']):
                categories["api_endpoints"].append(url)
            elif 'form' in path or 'submit' in path:
                categories["forms"].append(url)
            else:
                categories["other"].append(url)

        return categories

    def extract_javascript_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Extract URLs from JavaScript files

        Args:
            urls: List of JavaScript file URLs

        Returns:
            Dictionary containing extracted URLs
        """
        js_urls = [url for url in urls if '.js' in url.lower()]
        if not js_urls:
            return {"error": "No JavaScript URLs provided"}

        extracted_urls = []
        for js_url in js_urls[:10]:  # Limit to prevent overload
            try:
                # Use curl to fetch JS content (simple approach)
                result = subprocess.run(
                    ['curl', '-s', '--max-time', '10', js_url],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                if result.returncode == 0 and result.stdout:
                    # Simple regex to extract URLs from JS
                    url_pattern = r'["\']((?:https?://|/)[^"\']+)["\']'
                    matches = re.findall(url_pattern, result.stdout)
                    extracted_urls.extend(matches)

            except subprocess.TimeoutExpired:
                continue

        # Remove duplicates
        unique_urls = list(set(extracted_urls))

        return {
            "success": True,
            "js_files_analyzed": len(js_urls),
            "urls_extracted": len(unique_urls),
            "extracted_urls": unique_urls[:500]  # Limit for performance
        }

    def comprehensive_web_discovery(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive web discovery on a domain

        Args:
            domain: Target domain

        Returns:
            Dictionary containing all discovery results
        """
        discovery = {
            "domain": domain,
            "timestamp": None,  # Would be set by caller
            "discoveries": {}
        }

        # Wayback Machine discovery
        discovery["discoveries"]["wayback_gau"] = self.discover_urls_from_wayback(domain)
        discovery["discoveries"]["wayback_urls"] = self.extract_urls_from_wayback(domain)

        # Get URLs from Wayback results for further analysis
        all_urls = []
        for result in discovery["discoveries"].values():
            if "urls" in result:
                all_urls.extend(result["urls"])

        # Remove duplicates
        unique_urls = list(set(all_urls))

        # Probe discovered URLs
        if unique_urls:
            discovery["discoveries"]["http_probing"] = self.probe_http_endpoints(unique_urls[:100])  # Limit for performance

        # Extract JavaScript URLs and analyze them
        if unique_urls:
            js_analysis = self.extract_javascript_urls(unique_urls)
            discovery["discoveries"]["javascript_analysis"] = js_analysis

        # Crawl main domain
        main_url = f"https://{domain}"
        discovery["discoveries"]["site_crawling"] = self.crawl_website(main_url, depth=1)

        return discovery