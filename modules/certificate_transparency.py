from utils.osint_utils import OSINTUtils


class CertificateTransparency(OSINTUtils):
    def __init__(self):
        super().__init__()

    def search(self, domain):
        """
        Search crt.sh for certificate transparency logs for a domain (find subdomains, certs).
        Returns a list of certs and subdomains.
        """
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            # Use fallback-capable request so we can automatically retry via VPN/direct when desired
            resp = self.request_with_fallback('get', url, timeout=30, allow_fallback=True)
            if resp.status_code == 200:
                data = resp.json()
                certs = []
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    certs.append(entry)
                    for sub in name.split("\n"):
                        if sub.endswith(domain):
                            subdomains.add(sub.strip())
                return {"status": "success", "certs": certs, "subdomains": list(subdomains)}
            else:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
