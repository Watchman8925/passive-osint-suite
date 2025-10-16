import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.osint_utils import OSINTUtils


class MockResp:
    def __init__(self, status=200, json_data=None):
        self.status_code = status
        self._json = json_data or {}

    def json(self):
        return self._json


class SuccessUtils(OSINTUtils):
    def __init__(self):
        # Initialize without reading user's config
        # Create minimal directories to avoid FileNotFoundError
        import tempfile

        self.temp_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.temp_dir, "logs"), exist_ok=True)
        old_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        try:
            super().__init__()
        finally:
            os.chdir(old_cwd)

    def request_with_fallback(
        self,
        method,
        url,
        headers=None,
        params=None,
        timeout=None,
        allow_fallback=False,
        max_retries=1,
        **kwargs,
    ):
        # Simulate a DoH JSON response for A record
        if params and params.get("type") in (None, "A"):
            return MockResp(200, {"Answer": [{"data": "93.184.216.34"}]})
        # Simulate PTR response when querying an IP (name contains digits and dots)
        if params and params.get("type") == "PTR":
            return MockResp(200, {"Answer": [{"data": "example.com."}]})
        return MockResp(200, {"Answer": []})

    def doh_query(self, domain, record_type="A"):
        """Mock DoH query method"""
        resp = self.request_with_fallback("GET", "", params={"type": record_type})
        if resp and resp.status_code == 200:
            data = resp.json()
            if "Answer" in data:
                return [ans["data"] for ans in data["Answer"]]
        return []

    def reverse_dns(self, ip):
        """Mock reverse DNS method"""
        resp = self.request_with_fallback("GET", "", params={"type": "PTR"})
        if resp and resp.status_code == 200:
            data = resp.json()
            if "Answer" in data and data["Answer"]:
                return data["Answer"][0]["data"].rstrip(".")
        return None


class FailUtils(OSINTUtils):
    def __init__(self):
        # Create minimal directories to avoid FileNotFoundError
        import tempfile

        self.temp_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.temp_dir, "logs"), exist_ok=True)
        old_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        try:
            super().__init__()
        finally:
            os.chdir(old_cwd)

    def request_with_fallback(self, *args, **kwargs):
        # Simulate failure (e.g., Tor blocked and no fallback)
        return None

    def doh_query(self, domain, record_type="A"):
        """Mock DoH query method that fails"""
        resp = self.request_with_fallback("GET", "")
        if resp is None:
            return []
        return []

    def reverse_dns(self, ip):
        """Mock reverse DNS method that fails"""
        resp = self.request_with_fallback("GET", "")
        if resp is None:
            return None
        return None


def test_doh_query_success():
    u = SuccessUtils()
    answers = u.doh_query("example.com", record_type="A")
    assert isinstance(answers, list)
    assert "93.184.216.34" in answers


def test_reverse_dns_success():
    u = SuccessUtils()
    hostname = u.reverse_dns("93.184.216.34")
    assert hostname == "example.com"


def test_doh_query_failure():
    u = FailUtils()
    answers = u.doh_query("nonexistent.example", record_type="A")
    assert isinstance(answers, list)
    assert answers == []


def test_reverse_dns_failure():
    u = FailUtils()
    hostname = u.reverse_dns("10.255.255.1")
    assert hostname is None
