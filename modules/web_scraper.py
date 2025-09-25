from utils.osint_utils import OSINTUtils


class WebScraper(OSINTUtils):
    def __init__(self):
        super().__init__()

    def scrape(self, target, keywords=None):
        """
        Scrape a target website (news/blog/forum) for keywords.
        Returns a list of matching lines/snippets.
        """
        url = target if target.startswith('http') else f'https://{target}'
        try:
            resp = self.request_with_fallback('get', url, timeout=15, allow_fallback=True)
            if resp.status_code != 200:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
            text = resp.text
            results = []
            if keywords:
                for kw in keywords:
                    for line in text.splitlines():
                        if kw.lower() in line.lower():
                            results.append(line.strip())
            else:
                results = text.splitlines()[:20]  # Just show first 20 lines if no keywords
            return {"status": "success", "data": results}
        except Exception as e:
            return {"status": "error", "error": str(e)}
