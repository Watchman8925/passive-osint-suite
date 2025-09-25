import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.osint_utils import OSINTUtils


class MockResp:
    def __init__(self, status=200):
        self.status_code = status


class FailSess:
    def request(self, method, url, headers=None, params=None, timeout=None, **kwargs):
        raise Exception("fail")


class SuccessSess:
    def __init__(self, status=200):
        self._status = status

    def request(self, method, url, headers=None, params=None, timeout=None, **kwargs):
        return MockResp(self._status)


def test_fallback_order_and_logging(tmp_path, monkeypatch):
    # Create a temp log file path and ensure logs dir exists
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    # Monkeypatch logger file path by setting working dir
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        u = OSINTUtils()
        # Replace sessions: tor fails, vpn fails, direct succeeds
        u.session = FailSess()
        u.vpn_session = FailSess()
        u.direct_session = SuccessSess(200)
        # Ensure fallback config
        u.config.set("SETTINGS", "FALLBACK_TO_VPN", "True")
        # Call request_with_fallback allowing fallback
        resp = u.request_with_fallback(
            "get", "https://example.invalid/test", allow_fallback=True
        )
        assert resp is not None and resp.status_code == 200
        # Read the log file and check last structured entry
        with open("logs/osint_suite.log", "r") as lf:
            lines = [line.strip() for line in lf.readlines() if line.strip()]
            assert len(lines) > 0
            last = json.loads(lines[-1])
            assert last.get("fallback_transport") == "direct"
            assert last.get("url") == "https://example.invalid/test"
    finally:
        os.chdir(cwd)
