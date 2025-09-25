import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
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
        super().__init__()
    def request_with_fallback(self, method, url, headers=None, params=None, timeout=None, allow_fallback=False, max_retries=1, **kwargs):
        # Simulate a DoH JSON response for A record
        if params and params.get('type') in (None, 'A'):
            return MockResp(200, {'Answer': [{'data': '93.184.216.34'}]})
        # Simulate PTR response when querying an IP (name contains digits and dots)
        if params and params.get('type') == 'PTR':
            return MockResp(200, {'Answer': [{'data': 'example.com.'}]})
        return MockResp(200, {'Answer': []})

class FailUtils(OSINTUtils):
    def __init__(self):
        super().__init__()
    def request_with_fallback(self, *args, **kwargs):
        # Simulate failure (e.g., Tor blocked and no fallback)
        return None


def test_doh_query_success():
    u = SuccessUtils()
    answers = u.doh_query('example.com', record_type='A')
    assert isinstance(answers, list)
    assert '93.184.216.34' in answers


def test_reverse_dns_success():
    u = SuccessUtils()
    hostname = u.reverse_dns('93.184.216.34')
    assert hostname == 'example.com'


def test_doh_query_failure():
    u = FailUtils()
    answers = u.doh_query('nonexistent.example', record_type='A')
    assert isinstance(answers, list)
    assert answers == []


def test_reverse_dns_failure():
    u = FailUtils()
    hostname = u.reverse_dns('10.255.255.1')
    assert hostname is None
