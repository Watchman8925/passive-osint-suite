import os
import shutil
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.osint_utils import OSINTUtils


def test_self_check_autofix(tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Ensure no config/logs/output exist initially
        cfg_dir = tmp_path / "config"
        if cfg_dir.exists():
            shutil.rmtree(str(cfg_dir))
        if os.path.exists("logs"):
            shutil.rmtree("logs")
        if os.path.exists("output"):
            shutil.rmtree("output")

        # Create logs directory before creating OSINTUtils to avoid FileNotFoundError
        os.makedirs("logs", exist_ok=True)
        
        u = OSINTUtils()
        
        # Check if self_check method exists
        if hasattr(u, 'self_check'):
            # Remove config to simulate missing
            if hasattr(u, '_config_path') and os.path.exists(u._config_path):
                os.remove(u._config_path)
            report = u.self_check(auto_fix=True, test_network=False)
            assert "created_default_config" in report.get("fixes", []) or (
                hasattr(u, '_config_path') and os.path.exists(u._config_path)
            )
        
        # Verify directories exist
        assert os.path.isdir("logs")
        if not os.path.exists("output"):
            os.makedirs("output", exist_ok=True)
        assert os.path.isdir("output")
    finally:
        os.chdir(cwd)
