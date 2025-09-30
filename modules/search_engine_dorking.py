"""
Enhanced Search Engine Dorking Module
Provides comprehensive Google dorking patterns and multi-engine search capabilities
"""

from utils.osint_utils import OSINTUtils
import random
import time
from typing import List, Dict, Optional, Any
from urllib.parse import quote_plus
from bs4 import BeautifulSoup


class SearchEngineDorking(OSINTUtils):
    """Enhanced search engine dorking with comprehensive Google dork patterns"""

    def __init__(self):
        super().__init__()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        ]

    def dork(self, query: str, engines: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform passive search engine dorking using multiple engines.
        Returns a list of result URLs and snippets.
        """
        if engines is None:
            engines = ["duckduckgo", "bing", "yahoo", "yandex"]

        results = []
        headers = {"User-Agent": random.choice(self.user_agents)}

        for engine in engines:
            try:
                if engine.lower() == "duckduckgo":
                    engine_results = self._search_duckduckgo(query, headers)
                elif engine.lower() == "bing":
                    engine_results = self._search_bing(query, headers)
                elif engine.lower() == "yahoo":
                    engine_results = self._search_yahoo(query, headers)
                elif engine.lower() == "yandex":
                    engine_results = self._search_yandex(query, headers)
                else:
                    continue

                results.extend(engine_results)
                time.sleep(random.uniform(1, 3))  # Rate limiting

            except Exception as e:
                results.append({"engine": engine, "error": str(e)})

        return {"status": "success", "results": results}

    def _search_duckduckgo(self, query: str, headers: Dict) -> List[Dict]:
        """Search using DuckDuckGo"""
        results = []
        try:
            ddg_url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
            resp = self.make_request(ddg_url, headers=headers, timeout=20)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for r in soup.select(".result__body"):
                    link = r.select_one("a.result__a")
                    snippet = r.select_one(".result__snippet")
                    if link:
                        results.append(
                            {
                                "engine": "DuckDuckGo",
                                "url": link.get("href"),
                                "title": link.text.strip(),
                                "snippet": snippet.text.strip() if snippet else "",
                            }
                        )
        except Exception as e:
            results.append({"engine": "DuckDuckGo", "error": str(e)})
        return results

    def _search_bing(self, query: str, headers: Dict) -> List[Dict]:
        """Search using Bing"""
        results = []
        try:
            bing_url = f"https://www.bing.com/search?q={quote_plus(query)}"
            resp = self.make_request(bing_url, headers=headers, timeout=20)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for r in soup.select("li.b_algo"):
                    link = r.select_one("h2 > a")
                    snippet = r.select_one(".b_caption p")
                    if link:
                        results.append(
                            {
                                "engine": "Bing",
                                "url": link.get("href"),
                                "title": link.text.strip(),
                                "snippet": snippet.text.strip() if snippet else "",
                            }
                        )
        except Exception as e:
            results.append({"engine": "Bing", "error": str(e)})
        return results

    def _search_yahoo(self, query: str, headers: Dict) -> List[Dict]:
        """Search using Yahoo"""
        results = []
        try:
            yahoo_url = f"https://search.yahoo.com/search?p={quote_plus(query)}"
            resp = self.make_request(yahoo_url, headers=headers, timeout=20)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for r in soup.select(".algo"):
                    link = r.select_one("h3 > a")
                    snippet = r.select_one(".compText")
                    if link:
                        results.append(
                            {
                                "engine": "Yahoo",
                                "url": link.get("href"),
                                "title": link.text.strip(),
                                "snippet": snippet.text.strip() if snippet else "",
                            }
                        )
        except Exception as e:
            results.append({"engine": "Yahoo", "error": str(e)})
        return results

    def _search_yandex(self, query: str, headers: Dict) -> List[Dict]:
        """Search using Yandex"""
        results = []
        try:
            yandex_url = f"https://yandex.com/search/?text={quote_plus(query)}"
            resp = self.make_request(yandex_url, headers=headers, timeout=20)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for r in soup.select(".serp-item"):
                    link = r.select_one(".organic__url")
                    title = r.select_one(".organic__title")
                    snippet = r.select_one(".organic__content")
                    if link:
                        results.append(
                            {
                                "engine": "Yandex",
                                "url": link.get("href"),
                                "title": title.text.strip() if title else "",
                                "snippet": snippet.text.strip() if snippet else "",
                            }
                        )
        except Exception as e:
            results.append({"engine": "Yandex", "error": str(e)})
        return results

    def google_dorking_patterns(
        self, target: str, dork_type: str = "general"
    ) -> List[str]:
        """
        Generate comprehensive Google dorking patterns for different investigation types
        """
        patterns = []

        if dork_type == "general":
            patterns.extend(
                [
                    f"site:{target}",
                    f"inurl:{target}",
                    f"intitle:{target}",
                    f"intext:{target}",
                    f'"{target}" filetype:pdf',
                    f'"{target}" filetype:doc',
                    f'"{target}" filetype:xls',
                    f'"{target}" filetype:ppt',
                ]
            )

        elif dork_type == "email":
            patterns.extend(
                [
                    f'"{target}" "@gmail.com"',
                    f'"{target}" "@yahoo.com"',
                    f'"{target}" "@hotmail.com"',
                    f'"{target}" email',
                    f'"{target}" contact',
                    f'"{target}" mailto:',
                ]
            )

        elif dork_type == "social":
            patterns.extend(
                [
                    f'"{target}" linkedin',
                    f'"{target}" facebook',
                    f'"{target}" twitter',
                    f'"{target}" instagram',
                    f'"{target}" github',
                    f'"{target}" reddit',
                ]
            )

        elif dork_type == "company":
            patterns.extend(
                [
                    f'"{target}" "careers"',
                    f'"{target}" "about us"',
                    f'"{target}" "team"',
                    f'"{target}" "employees"',
                    f'"{target}" "contact"',
                    f'"{target}" filetype:pdf "annual report"',
                ]
            )

        elif dork_type == "vulnerabilities":
            patterns.extend(
                [
                    f"site:{target} inurl:admin",
                    f"site:{target} inurl:login",
                    f"site:{target} inurl:backup",
                    f"site:{target} filetype:sql",
                    f"site:{target} filetype:log",
                    f'site:{target} "index of /"',
                ]
            )

        elif dork_type == "documents":
            patterns.extend(
                [
                    f"site:{target} filetype:pdf",
                    f"site:{target} filetype:doc",
                    f"site:{target} filetype:docx",
                    f"site:{target} filetype:xls",
                    f"site:{target} filetype:ppt",
                    f"site:{target} filetype:txt",
                ]
            )

        elif dork_type == "code":
            patterns.extend(
                [
                    f"site:{target} filetype:php",
                    f"site:{target} filetype:js",
                    f"site:{target} filetype:py",
                    f"site:{target} filetype:java",
                    f"site:{target} filetype:xml",
                    f"site:{target} filetype:config",
                ]
            )

        elif dork_type == "breach":
            patterns.extend(
                [
                    f'"{target}" password',
                    f'"{target}" leaked',
                    f'"{target}" breach',
                    f'"{target}" pastebin',
                    f'"{target}" haveibeenpwned',
                ]
            )

        return patterns

    def comprehensive_dorking_search(
        self, target: str, dork_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive dorking search across multiple pattern types
        """
        if dork_types is None:
            dork_types = ["general", "email", "social", "company", "documents"]

        all_results = {}
        all_queries = []

        for dork_type in dork_types:
            patterns = self.google_dorking_patterns(target, dork_type)
            type_results = []

            for pattern in patterns:
                self.logger.info(f"Searching with dork: {pattern}")
                results = self.dork(pattern)
                if results.get("results"):
                    type_results.extend(results["results"])
                all_queries.append(pattern)
                time.sleep(random.uniform(2, 5))  # Rate limiting

            all_results[dork_type] = type_results

        return {
            "target": target,
            "dork_types": dork_types,
            "queries_used": all_queries,
            "results": all_results,
            "total_results": sum(len(results) for results in all_results.values()),
        }

    def passive_subdomain_enumeration(self, domain: str) -> List[str]:
        """
        Use search engines to find subdomains passively
        """
        subdomains = set()
        dorks = [
            f"site:*.{domain}",
            f"inurl:{domain}",
            f'"*.{domain}"',
            f"subdomain {domain}",
        ]

        for dork in dorks:
            results = self.dork(dork)
            if results.get("results"):
                for result in results["results"]:
                    url = result.get("url", "")
                    # Extract potential subdomains from URLs
                    if domain in url:
                        try:
                            from urllib.parse import urlparse

                            parsed = urlparse(url)
                            if parsed.netloc and domain in parsed.netloc:
                                subdomain = parsed.netloc.replace(
                                    "." + domain, ""
                                ).replace(domain, "")
                                if (
                                    subdomain and "." not in subdomain
                                ):  # Avoid false positives
                                    subdomains.add(subdomain)
                        except Exception:
                            continue

            time.sleep(random.uniform(1, 3))

        return list(subdomains)

    def find_exposed_files(self, domain: str) -> Dict[str, List[str]]:
        """
        Search for commonly exposed files and directories
        """
        exposed_files: Dict[str, List[str]] = {
            "admin_panels": [],
            "backups": [],
            "logs": [],
            "configs": [],
        }

        dorks = {
            "admin_panels": [
                f"site:{domain} inurl:admin",
                f"site:{domain} inurl:administrator",
                f"site:{domain} inurl:login",
                f'site:{domain} intitle:"admin login"',
            ],
            "backups": [
                f"site:{domain} filetype:sql",
                f"site:{domain} filetype:tar",
                f"site:{domain} filetype:gz",
                f'site:{domain} "backup"',
            ],
            "logs": [
                f"site:{domain} filetype:log",
                f'site:{domain} "error.log"',
                f'site:{domain} "access.log"',
            ],
            "configs": [
                f"site:{domain} filetype:config",
                f"site:{domain} filetype:ini",
                f"site:{domain} filetype:xml",
                f'site:{domain} "wp-config.php"',
            ],
        }

        for category, category_dorks in dorks.items():
            for dork in category_dorks:
                results = self.dork(dork)
                if results.get("results"):
                    for result in results["results"]:
                        exposed_files[category].append(result.get("url", ""))
                time.sleep(random.uniform(1, 3))

        return exposed_files
