from utils.osint_utils import OSINTUtils


class PassiveDNSEnum(OSINTUtils):
    def __init__(self):
        super().__init__()

    def enumerate(self, domain):
        """
        Enumerate subdomains using crt.sh and DNS records (no API, OPSEC safe).
        Returns a list of subdomains.
        """
        subdomains = set()
        # crt.sh (passive)
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self.tor_get(url, timeout=30)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            if sub.endswith(domain):
                                subdomains.add(sub.strip())
                except ValueError:
                    # Non-JSON response - skip
                    pass
        except Exception as e:
            subdomains.add(f"[crt.sh error] {e}")

        # Wayback Machine hostnames (passive)
        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            resp = self.tor_get(cdx_url, timeout=30)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for entry in data[1:]:
                        original = entry[0]
                        # Extract hostname
                        from urllib.parse import urlparse

                        parsed = urlparse(original)
                        hostname = parsed.hostname
                        if hostname and hostname.endswith(domain):
                            subdomains.add(hostname)
                except ValueError:
                    pass
        except Exception as e:
            subdomains.add(f"[wayback error] {e}")

        return {"status": "success", "subdomains": sorted(list(subdomains))}
