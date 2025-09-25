import os
import shutil
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.osint_utils import OSINTUtils


def test_config_initialization(tmp_path):
    # Create an isolated workspace
    cfg_dir = tmp_path / 'config'
    # Ensure nothing exists
    if cfg_dir.exists():
        shutil.rmtree(str(cfg_dir))

    cfg_path = cfg_dir / 'config.ini'
    # Instantiate OSINTUtils with this path
    u = OSINTUtils(config_path=str(cfg_path))

    # Verify config file was created
    assert cfg_path.exists()
    # Verify logs and output directories were created
    base = os.path.dirname(str(cfg_path))
    logs_dir = os.path.join(os.path.dirname(base), 'logs')
    output_dir = os.path.join(os.path.dirname(base), 'output')
    assert os.path.isdir(logs_dir)
    assert os.path.isdir(output_dir)

    # Verify defaults in config
    assert u.config.get('SETTINGS', 'ENABLE_ACTIVE') == 'False'
    assert 'DOH_PROVIDER' in u.config['SETTINGS']
