from utils.osint_utils import OSINTUtils


class WhoisHistory(OSINTUtils):
    def __init__(self):
        super().__init__()

    def get_history(self, domain):
        """
        Scrape public WHOIS history from viewdns.info (no login, OPSEC safe).
        Returns a list of WHOIS history records.
        """
        from bs4 import BeautifulSoup

        url = f"https://viewdns.info/iphistory/?domain={domain}"
        try:
            resp = self.request_with_fallback(
                "get", url, timeout=20, allow_fallback=True
            )
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                history = []
                table = soup.find("table", {"border": "1"})
                if table:
                    for row in table.find_all("tr")[1:]:
                        cols = row.find_all("td")
                        if len(cols) >= 2:
                            history.append(
                                {
                                    "ip": cols[0].text.strip(),
                                    "date": cols[1].text.strip(),
                                }
                            )
                return {"status": "success", "history": history}
            else:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
