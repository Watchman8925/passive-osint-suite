from utils.osint_utils import OSINTUtils


class WaybackMachine(OSINTUtils):
    def __init__(self):
        super().__init__()

    def fetch_snapshots(self, url):
        """
        Fetch historical snapshots for a URL from archive.org Wayback Machine.
        Returns a list of snapshot timestamps and URLs.
        """
        api_url = f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp,original&collapse=digest"
        try:
            resp = self.request_with_fallback('get', api_url, timeout=30, allow_fallback=True)
            if resp.status_code == 200:
                data = resp.json()
                snapshots = []
                for entry in data[1:]:
                    timestamp, original = entry
                    snapshots.append({
                        "timestamp": timestamp,
                        "snapshot_url": f"https://web.archive.org/web/{timestamp}/{original}"
                    })
                return {"status": "success", "snapshots": snapshots}
            else:
                return {"status": "error", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
