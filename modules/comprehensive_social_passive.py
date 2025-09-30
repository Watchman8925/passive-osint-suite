"""
Comprehensive Social Media Passive Intelligence Module
Monitor public profiles across multiple social media platforms without authentication
"""

from utils.osint_utils import OSINTUtils
from bs4 import BeautifulSoup


class ComprehensiveSocialPassive(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.platforms = {
            "twitter": {"url": "https://twitter.com", "name": "Twitter/X"},
            "linkedin": {"url": "https://linkedin.com/in", "name": "LinkedIn"},
            "instagram": {"url": "https://instagram.com", "name": "Instagram"},
            "facebook": {"url": "https://facebook.com", "name": "Facebook"},
            "tiktok": {"url": "https://tiktok.com/@", "name": "TikTok"},
            "youtube": {"url": "https://youtube.com/@", "name": "YouTube"},
            "medium": {"url": "https://medium.com/@", "name": "Medium"},
            "reddit": {"url": "https://reddit.com/user", "name": "Reddit"},
            "discord": {"url": "https://discord.com/users", "name": "Discord"},
            "telegram": {"url": "https://t.me", "name": "Telegram"},
        }

    def search_all_platforms(self, username, include_private=False):
        """
        Search for a username across all supported social media platforms
        Returns found profiles and their public information
        """
        results = {
            "username": username,
            "platforms_checked": len(self.platforms),
            "found_profiles": [],
            "not_found": [],
            "errors": [],
        }

        for platform_key, platform_info in self.platforms.items():
            try:
                profile_result = self.check_platform_profile(platform_key, username)
                if profile_result["found"]:
                    results["found_profiles"].append(
                        {
                            "platform": platform_info["name"],
                            "url": profile_result["url"],
                            "exists": True,
                            "public_info": profile_result.get("public_info", {}),
                        }
                    )
                else:
                    results["not_found"].append(platform_info["name"])

            except Exception as e:
                results["errors"].append(
                    {"platform": platform_info["name"], "error": str(e)}
                )

        results["success_rate"] = (
            len(results["found_profiles"]) / results["platforms_checked"]
        )
        return results

    def check_platform_profile(self, platform, username):
        """
        Check if a profile exists on a specific platform
        """
        if platform == "twitter":
            return self.check_twitter_profile(username)
        elif platform == "linkedin":
            return self.check_linkedin_profile(username)
        elif platform == "instagram":
            return self.check_instagram_profile(username)
        elif platform == "facebook":
            return self.check_facebook_profile(username)
        elif platform == "tiktok":
            return self.check_tiktok_profile(username)
        elif platform == "youtube":
            return self.check_youtube_profile(username)
        elif platform == "medium":
            return self.check_medium_profile(username)
        elif platform == "reddit":
            return self.check_reddit_profile(username)
        elif platform == "discord":
            return self.check_discord_profile(username)
        elif platform == "telegram":
            return self.check_telegram_profile(username)
        else:
            return {"found": False, "url": "", "public_info": {}}

    def check_twitter_profile(self, username):
        """Check Twitter/X profile"""
        url = f"https://twitter.com/{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "profile" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                name_elem = soup.select_one('[data-testid="User-Name"]')
                if name_elem:
                    public_info["name"] = name_elem.text.strip()

                bio_elem = soup.select_one('[data-testid="user-biography"]')
                if bio_elem:
                    public_info["bio"] = bio_elem.text.strip()

                location_elem = soup.select_one('[data-testid="user-location"]')
                if location_elem:
                    public_info["location"] = location_elem.text.strip()

                join_date_elem = soup.select_one('[data-testid="user-join-date"]')
                if join_date_elem:
                    public_info["join_date"] = join_date_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_linkedin_profile(self, username):
        """Check LinkedIn profile"""
        url = f"https://linkedin.com/in/{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "linkedin" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                name_elem = soup.select_one("h1, .name")
                if name_elem:
                    public_info["name"] = name_elem.text.strip()

                title_elem = soup.select_one(".headline, .subline")
                if title_elem:
                    public_info["title"] = title_elem.text.strip()

                location_elem = soup.select_one(".location")
                if location_elem:
                    public_info["location"] = location_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_instagram_profile(self, username):
        """Check Instagram profile"""
        url = f"https://instagram.com/{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "instagram" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                name_elem = soup.select_one("h1, .name")
                if name_elem:
                    public_info["name"] = name_elem.text.strip()

                bio_elem = soup.select_one(".-vDIg span")
                if bio_elem:
                    public_info["bio"] = bio_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_facebook_profile(self, username):
        """Check Facebook profile"""
        url = f"https://facebook.com/{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "facebook" in resp.text.lower()

            return {"found": found, "url": url, "public_info": {}}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_tiktok_profile(self, username):
        """Check TikTok profile"""
        url = f"https://tiktok.com/@{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "tiktok" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                name_elem = soup.select_one("h1, .name")
                if name_elem:
                    public_info["name"] = name_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_youtube_profile(self, username):
        """Check YouTube channel"""
        url = f"https://youtube.com/@{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "youtube" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                name_elem = soup.select_one("h1, .channel-name")
                if name_elem:
                    public_info["name"] = name_elem.text.strip()

                subs_elem = soup.select_one(".subscriber-count")
                if subs_elem:
                    public_info["subscribers"] = subs_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_medium_profile(self, username):
        """Check Medium profile"""
        url = f"https://medium.com/@{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "medium" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                name_elem = soup.select_one("h1, .name")
                if name_elem:
                    public_info["name"] = name_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_reddit_profile(self, username):
        """Check Reddit profile"""
        url = f"https://www.reddit.com/user/{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "reddit" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                karma_elem = soup.select_one(".karma")
                if karma_elem:
                    public_info["karma"] = karma_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}

    def check_discord_profile(self, username):
        """Check Discord profile (limited due to Discord's design)"""
        # Discord user profiles are not publicly accessible without user ID
        # This is more of a placeholder for future implementation
        return {
            "found": False,
            "url": f"https://discord.com/users/{username}",
            "public_info": {},
            "note": "Discord profiles require user ID for direct access",
        }

    def check_telegram_profile(self, username):
        """Check Telegram profile"""
        url = f"https://t.me/{username}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=10, allow_fallback=True
            )
            found = resp.status_code == 200 and "telegram" in resp.text.lower()

            public_info = {}
            if found:
                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract basic public info
                name_elem = soup.select_one(".tgme_page_title")
                if name_elem:
                    public_info["name"] = name_elem.text.strip()

                desc_elem = soup.select_one(".tgme_page_description")
                if desc_elem:
                    public_info["description"] = desc_elem.text.strip()

            return {"found": found, "url": url, "public_info": public_info}
        except Exception as e:
            return {"found": False, "url": url, "error": str(e), "public_info": {}}
