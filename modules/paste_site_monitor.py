from utils.osint_utils import OSINTUtils


class PasteSiteMonitor(OSINTUtils):
    def __init__(self):
        super().__init__()

    def search_pastes(self, keyword):
        """
        Scrape Pastebin public search for keyword leaks (no login, OPSEC safe).
        Returns a list of paste URLs and snippets.
        """
        from bs4 import BeautifulSoup
        url = f"https://pastebin.com/search?q={keyword}"
        try:
            resp = self.request_with_fallback('get', url, timeout=20, allow_fallback=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                pastes = []
                for r in soup.select(".result table tr")[1:]:
                    cols = r.find_all("td")
                    if len(cols) >= 2:
                        link = cols[0].find("a")
                        snippet = cols[1].text.strip()
                        if link:
                            pastes.append({
                                "url": f"https://pastebin.com{link.get('href')}",
                                "snippet": snippet
                            })
                return {"status": "success", "pastes": pastes}
            else:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
