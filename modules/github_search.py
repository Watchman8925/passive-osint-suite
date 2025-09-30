from utils.osint_utils import OSINTUtils


class GitHubSearch(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def search(self, keyword):
        """
        Search GitHub for public repositories matching a keyword (no login, OPSEC safe).
        Returns a list of repo URLs and descriptions.
        """
        from bs4 import BeautifulSoup

        url = f"https://github.com/search?q={keyword}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=20, allow_fallback=True
            )
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                repos = []
                for r in soup.select("ul.repo-list li"):
                    link = r.select_one("a.v-align-middle")
                    desc = r.select_one("p.mb-1")
                    if link:
                        repos.append(
                            {
                                "url": f"https://github.com{link.get('href')}",
                                "description": desc.text.strip() if desc else "",
                            }
                        )
                return {"status": "success", "data": repos}
            else:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
