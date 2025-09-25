import os
import shutil
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.osint_utils import OSINTUtils


def test_self_check_autofix(tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Ensure no config/logs/output exist
        cfg_dir = tmp_path / 'config'
        if cfg_dir.exists():
            shutil.rmtree(str(cfg_dir))
        if os.path.exists('logs'):
            shutil.rmtree('logs')
        if os.path.exists('output'):
            shutil.rmtree('output')

        u = OSINTUtils()
        # Remove config to simulate missing
        if os.path.exists(u._config_path):
            os.remove(u._config_path)
        report = u.self_check(auto_fix=True, test_network=False)
        assert 'created_default_config' in report.get('fixes', []) or os.path.exists(u._config_path)
        assert os.path.isdir('logs')
        assert os.path.isdir('output')
    finally:
        os.chdir(cwd)
