from utils.osint_utils import OSINTUtils


class PublicBreachSearch(OSINTUtils):
    def __init__(self):
        super().__init__()

    def search(self, email_or_domain):
        """
        Search public breach aggregation sites for leaks (no login, OPSEC safe).
        Returns a list of breach records.
        """
        url = f"https://haveibeenpwned.com/unifiedsearch/{email_or_domain}"
        try:
            resp = self.request_with_fallback('get', url, timeout=20, allow_fallback=True)
            if resp.status_code == 200:
                data = resp.json()
                breaches = []
                for b in data.get("Breaches", []):
                    breaches.append({
                        "title": b.get("Title"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "description": b.get("Description")
                    })
                return {"status": "success", "breaches": breaches}
            else:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
