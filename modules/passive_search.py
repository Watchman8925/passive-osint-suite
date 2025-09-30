"""
Passive Search Intelligence Module
Google dorking, social media, and open source intelligence gathering
"""

import time
import urllib.parse
from datetime import datetime

from utils.osint_utils import OSINTUtils


class PassiveSearchIntelligence(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def analyze_target(self, target, target_type="domain"):
        """Comprehensive passive search analysis"""
        self.logger.info(f"Starting passive search analysis for: {target}")

        self.results = {
            "target": target,
            "target_type": target_type,
            "timestamp": datetime.now().isoformat(),
            "google_dorking": self.google_dorking_search(target, target_type),
            "social_media": self.social_media_search(target, target_type),
            "pastebin_search": self.pastebin_search(target),
            "github_search": self.github_search(target),
            "news_mentions": self.news_search(target),
            "job_postings": self.job_posting_search(target),
            "court_records": self.court_records_search(target),
            "professional_profiles": self.professional_profile_search(target),
        }

        return self.results

    def google_dorking_search(self, target, target_type):
        """Perform Google dorking searches"""
        google_key = self.get_api_key("GOOGLESEARCH_API_KEY")

        if not google_key:
            return self.manual_google_dorking(target, target_type)

        # Google Custom Search API dorking
        dork_results = {}

        # Define dork queries based on target type
        if target_type == "domain":
            dorks = [
                f"site:{target} filetype:pdf",
                f'site:{target} intitle:"index of"',
                f"site:{target} inurl:admin",
                f"site:{target} inurl:login",
                f'site:{target} "confidential" OR "sensitive"',
                f"site:{target} filetype:doc OR filetype:docx",
                f"site:{target} filetype:xls OR filetype:xlsx",
                f'"{target}" site:pastebin.com',
                f'"{target}" site:github.com',
            ]
        elif target_type == "email":
            dorks = [
                f'"{target}"',
                f'"{target}" site:linkedin.com',
                f'"{target}" site:twitter.com',
                f'"{target}" site:facebook.com',
                f'"{target}" breach OR leaked OR dump',
                f'"{target}" site:pastebin.com',
                f'"{target}" password OR credentials',
            ]
        elif target_type == "company":
            dorks = [
                f'"{target}" employees OR staff',
                f'"{target}" executive OR CEO OR CTO',
                f'"{target}" "org chart" OR "organizational chart"',
                f'"{target}" confidential OR internal',
                f'"{target}" site:sec.gov',
                f'"{target}" lawsuit OR litigation',
                f'"{target}" site:linkedin.com/company',
            ]
        else:
            dorks = [f'"{target}"']

        # Perform searches
        for dork in dorks[:5]:  # Limit to avoid API limits
            try:
                url = "https://www.googleapis.com/customsearch/v1"
                params = {"key": google_key, "q": dork, "num": 10}

                response = self.make_request(url, params=params)
                if response:
                    data = response.json()
                    items = data.get("items", [])

                    dork_results[dork] = []
                    for item in items:
                        dork_results[dork].append(
                            {
                                "title": item.get("title"),
                                "link": item.get("link"),
                                "snippet": item.get("snippet"),
                                "displayLink": item.get("displayLink"),
                            }
                        )

                time.sleep(1)  # Rate limiting

            except Exception as e:
                self.logger.error(f"Google dork search failed for '{dork}': {e}")
                continue

        return {
            "total_dorks": len(dorks),
            "executed_dorks": len(dork_results),
            "results": dork_results,
        }

    def manual_google_dorking(self, target, target_type):
        """Manual Google dorking without API"""
        return {
            "message": "Google API key not configured",
            "suggested_manual_dorks": self.get_suggested_dorks(target, target_type),
        }

    def get_suggested_dorks(self, target, target_type):
        """Get suggested Google dorks for manual searching"""
        if target_type == "domain":
            return [
                f"site:{target} filetype:pdf",
                f'site:{target} intitle:"index of"',
                f"site:{target} inurl:admin OR inurl:login",
                f'site:{target} "confidential" OR "internal"',
                f'"{target}" site:pastebin.com',
                f'"{target}" site:github.com',
            ]
        elif target_type == "email":
            return [
                f'"{target}" site:linkedin.com',
                f'"{target}" breach OR leak',
                f'"{target}" site:haveibeenpwned.com',
                f'"{target}" password OR credentials',
                f'"{target}" site:pastebin.com',
            ]
        elif target_type == "company":
            return [
                f'"{target}" employees list',
                f'"{target}" organizational chart',
                f'"{target}" site:sec.gov',
                f'"{target}" lawsuit OR litigation',
                f'"{target}" site:linkedin.com/company',
            ]
        else:
            return [f'"{target}"']

    def social_media_search(self, target, target_type):
        """Search social media platforms"""
        social_results = {}

        platforms = {
            "linkedin": "https://www.linkedin.com/search/results/all/",
            "twitter": "https://twitter.com/search",
            "facebook": "https://www.facebook.com/search/top/",
            "instagram": "https://www.instagram.com/web/search/topsearch/",
            "reddit": "https://www.reddit.com/search/",
        }

        for platform, base_url in platforms.items():
            try:
                # Check if profiles exist by making requests
                if platform == "linkedin" and target_type == "company":
                    search_url = f"https://www.linkedin.com/company/{target.lower().replace(' ', '-')}"
                elif platform == "twitter":
                    search_url = f"https://twitter.com/{target.replace('@', '').replace(' ', '')}"
                elif platform == "facebook":
                    search_url = f"https://www.facebook.com/{target.replace(' ', '')}"
                else:
                    continue  # Skip complex searches for now

                response = self.make_request(search_url, timeout=10)
                if response and response.status_code == 200:
                    social_results[platform] = {
                        "found": True,
                        "url": search_url,
                        "status": "Profile/Page exists",
                    }
                else:
                    social_results[platform] = {
                        "found": False,
                        "searched_url": search_url,
                        "status": "Not found or inaccessible",
                    }

                time.sleep(2)  # Rate limiting

            except Exception as e:
                social_results[platform] = {"error": str(e), "status": "Search failed"}

        return social_results

    def pastebin_search(self, target):
        """Search Pastebin for mentions"""
        try:
            # Pastebin doesn't have a public API for searching
            # We'll use Google to search Pastebin
            search_query = f'"{target}" site:pastebin.com'

            # Manual search suggestion
            return {
                "search_performed": False,
                "suggested_search": search_query,
                "manual_search_url": f"https://www.google.com/search?q={urllib.parse.quote(search_query)}",
                "note": "Pastebin requires manual searching or premium access",
            }

        except Exception as e:
            self.logger.error(f"Pastebin search failed: {e}")
            return {"error": str(e)}

    def github_search(self, target):
        """Search GitHub for code and repositories"""
        try:
            # GitHub public search
            search_results = []

            # Search for repositories
            repo_url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(target)}"
            response = self.make_request(repo_url)

            if response:
                data = response.json()
                repos = data.get("items", [])

                for repo in repos[:10]:  # Limit results
                    search_results.append(
                        {
                            "type": "repository",
                            "name": repo.get("name"),
                            "full_name": repo.get("full_name"),
                            "description": repo.get("description"),
                            "url": repo.get("html_url"),
                            "owner": repo.get("owner", {}).get("login"),
                            "language": repo.get("language"),
                            "stars": repo.get("stargazers_count"),
                        }
                    )

            # Search for code
            time.sleep(2)  # Rate limiting
            code_url = (
                f"https://api.github.com/search/code?q={urllib.parse.quote(target)}"
            )
            response = self.make_request(code_url)

            if response:
                data = response.json()
                code_results = data.get("items", [])

                for code in code_results[:10]:  # Limit results
                    search_results.append(
                        {
                            "type": "code",
                            "name": code.get("name"),
                            "path": code.get("path"),
                            "repository": code.get("repository", {}).get("full_name"),
                            "url": code.get("html_url"),
                            "score": code.get("score"),
                        }
                    )

            return {"total_results": len(search_results), "results": search_results}

        except Exception as e:
            self.logger.error(f"GitHub search failed: {e}")
            return {"error": str(e)}

    def news_search(self, target):
        """Search news mentions"""
        try:
            google_key = self.get_api_key("GOOGLESEARCH_API_KEY")

            if not google_key:
                return {
                    "error": "No Google API key",
                    "suggested_search": f'"{target}" news',
                    "manual_search_url": f"https://news.google.com/search?q={urllib.parse.quote(target)}",
                }

            # Use Google Custom Search for news
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "key": google_key,
                "q": f'"{target}" news',
                "num": 10,
                "sort": "date",
            }

            response = self.make_request(url, params=params)
            if response:
                data = response.json()
                items = data.get("items", [])

                news_results = []
                for item in items:
                    news_results.append(
                        {
                            "title": item.get("title"),
                            "link": item.get("link"),
                            "snippet": item.get("snippet"),
                            "displayLink": item.get("displayLink"),
                            "publishedDate": item.get("pagemap", {})
                            .get("metatags", [{}])[0]
                            .get("article:published_time"),
                        }
                    )

                return {"total_results": len(news_results), "news_items": news_results}

        except Exception as e:
            self.logger.error(f"News search failed: {e}")
            return {"error": str(e)}

    def job_posting_search(self, target):
        """Search job postings mentioning target"""
        try:
            # Search major job boards
            job_results = {}

            job_sites = [
                "linkedin.com/jobs",
                "indeed.com",
                "glassdoor.com",
                "monster.com",
            ]

            google_key = self.get_api_key("GOOGLESEARCH_API_KEY")

            if google_key:
                for site in job_sites:
                    search_query = f'"{target}" site:{site}'

                    url = "https://www.googleapis.com/customsearch/v1"
                    params = {"key": google_key, "q": search_query, "num": 5}

                    response = self.make_request(url, params=params)
                    if response:
                        data = response.json()
                        items = data.get("items", [])

                        job_results[site] = []
                        for item in items:
                            job_results[site].append(
                                {
                                    "title": item.get("title"),
                                    "link": item.get("link"),
                                    "snippet": item.get("snippet"),
                                }
                            )

                    time.sleep(1)  # Rate limiting

            else:
                job_results = {
                    "manual_searches": [
                        f'"{target}" site:{site}' for site in job_sites
                    ],
                    "note": "No Google API key - perform manual searches",
                }

            return job_results

        except Exception as e:
            self.logger.error(f"Job posting search failed: {e}")
            return {"error": str(e)}

    def court_records_search(self, target):
        """Search court records and legal documents"""
        try:
            # Public court record sources
            court_sources = ["justia.com", "courtlistener.com", "pacer.gov", "sec.gov"]

            google_key = self.get_api_key("GOOGLESEARCH_API_KEY")
            court_results = {}

            if google_key:
                for source in court_sources:
                    search_query = f'"{target}" site:{source}'

                    url = "https://www.googleapis.com/customsearch/v1"
                    params = {"key": google_key, "q": search_query, "num": 5}

                    response = self.make_request(url, params=params)
                    if response:
                        data = response.json()
                        items = data.get("items", [])

                        court_results[source] = []
                        for item in items:
                            court_results[source].append(
                                {
                                    "title": item.get("title"),
                                    "link": item.get("link"),
                                    "snippet": item.get("snippet"),
                                }
                            )

                    time.sleep(1)  # Rate limiting

            else:
                court_results = {
                    "manual_searches": [
                        f'"{target}" site:{source}' for source in court_sources
                    ],
                    "note": "No Google API key - perform manual searches",
                }

            return court_results

        except Exception as e:
            self.logger.error(f"Court records search failed: {e}")
            return {"error": str(e)}

    def professional_profile_search(self, target):
        """Search professional networking sites"""
        try:
            professional_results = {}

            # Professional sites
            prof_sites = [
                "linkedin.com",
                "xing.com",
                "viadeo.com",
                "behance.net",
                "dribbble.com",
                "stackoverflow.com",
            ]

            for site in prof_sites:
                try:
                    # Simple check if profile exists
                    if site == "linkedin.com":
                        profile_url = f"https://www.linkedin.com/in/{target.lower().replace(' ', '-')}"
                    elif site == "stackoverflow.com":
                        profile_url = f"https://stackoverflow.com/users/{target}"
                    else:
                        continue  # Skip complex profile URL generation

                    response = self.make_request(profile_url, timeout=10)

                    professional_results[site] = {
                        "profile_checked": profile_url,
                        "exists": response is not None and response.status_code == 200,
                    }

                    time.sleep(2)  # Rate limiting

                except Exception as e:
                    professional_results[site] = {"error": str(e)}

            return professional_results

        except Exception as e:
            self.logger.error(f"Professional profile search failed: {e}")
            return {"error": str(e)}

    def generate_report(self):
        """Generate comprehensive passive search report"""
        if not self.results:
            return "No analysis results available"

        report = f"""
# Passive Search Intelligence Report: {self.results['target']}
Generated: {self.results['timestamp']}

## Google Dorking Results
"""

        # Add Google dorking results
        google_results = self.results.get("google_dorking", {})
        executed_dorks = google_results.get("executed_dorks", 0)

        report += f"Executed Dorks: {executed_dorks}\n"

        if "suggested_manual_dorks" in google_results:
            report += "\n### Suggested Manual Searches:\n"
            for dork in google_results["suggested_manual_dorks"]:
                report += f"- {dork}\n"

        # Add social media results
        social_media = self.results.get("social_media", {})
        report += "\n## Social Media Presence\n"

        for platform, result in social_media.items():
            if result.get("found"):
                report += f"✅ {platform.title()}: {result.get('url')}\n"
            else:
                report += f"❌ {platform.title()}: Not found\n"

        # Add GitHub results
        github_results = self.results.get("github_search", {})
        if "total_results" in github_results:
            report += "\n## GitHub Results\n"
            report += f"Total Results: {github_results['total_results']}\n"

            for result in github_results.get("results", [])[:5]:
                report += f"- {result.get('type', 'unknown').title()}: {result.get('name', 'N/A')}\n"
                if "url" in result:
                    report += f"  URL: {result['url']}\n"

        return report
