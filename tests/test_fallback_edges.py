import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.osint_utils import OSINTUtils


class FailResp:
    def __init__(self):
        self.status_code = 500

class FailSess:
    def request(self, *args, **kwargs):
        raise Exception('tor fail')

class VPNSuccessSess:
    def request(self, method, url, headers=None, params=None, timeout=None, **kwargs):
        class R:
            status_code = 200
            def json(self):
                return {'ok': True}
        return R()


def test_fallback_vpn_success(tmp_path, monkeypatch):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        u = OSINTUtils()
        u.session = FailSess()
        u.vpn_session = VPNSuccessSess()
        u.direct_session = FailSess()
        u.config.set('SETTINGS', 'FALLBACK_TO_VPN', 'True')
        resp = u.request_with_fallback('get', 'https://example.invalid/fallback', allow_fallback=True, max_retries=1)
        assert resp is not None
        # check structured log exists and mentions vpn
        with open('logs/osint_suite.log', 'r') as lf:
            found = False
            for line in lf:
                if 'fallback_transport' in line and 'vpn' in line:
                    found = True
                    break
            assert found
    finally:
        os.chdir(cwd)


def test_temporary_enable_flow(tmp_path):
    # Verify temporary enabling does not raise and domain analyze runs with passive-only defaults
    from modules import get_module
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Ensure config created
        u = OSINTUtils()
        # Create an instance of the suite module and run analyze_domain with ENABLE_ACTIVE False
        dr = get_module('domain_recon')
        u.config['SETTINGS']['ENABLE_ACTIVE'] = 'False'
        # Call analyze_domain (will use DoH and passive flows)
        res = dr.analyze_domain('example.com')
        assert isinstance(res, dict)
    finally:
        os.chdir(cwd)
