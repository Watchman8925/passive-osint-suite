from utils.osint_utils import OSINTUtils


class SocialMediaFootprint(OSINTUtils):
    def __init__(self):
        super().__init__()

    def scrape_profiles(self, name_or_handle):
        """
        Scrape public Twitter and Reddit profiles for a handle (no login, OPSEC safe).
        Returns a list of found profiles and basic info.
        """
        profiles = []
        # Twitter
        twitter_url = f"https://twitter.com/{name_or_handle}"
        try:
            resp = self.request_with_fallback('get', twitter_url, timeout=15, allow_fallback=True)
            if resp.status_code == 200 and 'profile' in resp.text:
                profiles.append({"platform": "Twitter", "url": twitter_url})
        except Exception as e:
            profiles.append({"platform": "Twitter", "error": str(e)})
        # Reddit
        reddit_url = f"https://www.reddit.com/user/{name_or_handle}"
        try:
            resp = self.request_with_fallback('get', reddit_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"}, allow_fallback=True)
            if resp.status_code == 200 and 'Reddit' in resp.text:
                profiles.append({"platform": "Reddit", "url": reddit_url})
        except Exception as e:
            profiles.append({"platform": "Reddit", "error": str(e)})
        return {"status": "success", "profiles": profiles}
