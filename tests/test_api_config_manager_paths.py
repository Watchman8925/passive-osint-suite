"""Ensure the API configuration manager stores files in configurable locations."""

from __future__ import annotations

from security.api_key_manager import APIConfigurationManager


def test_manager_uses_environment_config_dir(tmp_path, monkeypatch):
    custom_dir = tmp_path / "config"
    monkeypatch.setenv("OSINT_CONFIG_DIR", str(custom_dir))

    manager = APIConfigurationManager()

    assert manager.config_file.parent == custom_dir
    assert manager.status_file.parent == custom_dir
    assert custom_dir.exists()


def test_manager_accepts_explicit_config_dir(tmp_path):
    explicit_dir = tmp_path / "explicit-config"

    manager = APIConfigurationManager(config_dir=explicit_dir)

    assert manager.config_dir == explicit_dir
    assert manager.config_file.parent == explicit_dir
    assert explicit_dir.exists()
