"""Tests covering the AppConfig database URL safeguards."""

from __future__ import annotations

import importlib
import sys

import pytest

MODULE_NAME = "api.api_server"


def _reset_module() -> None:
    sys.modules.pop(MODULE_NAME, None)


def test_app_config_requires_database_url_in_production(monkeypatch):
    _reset_module()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("OSINT_SECRET_KEY", "prod-secret-key-with-ample-length-123456")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with pytest.raises(
        ValueError, match="DATABASE_URL environment variable must be set"
    ):
        importlib.import_module(MODULE_NAME)

    _reset_module()


def test_app_config_uses_safe_default_for_development(monkeypatch, caplog):
    _reset_module()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("OSINT_SECRET_KEY", "dev-secret-key-with-ample-length-123456")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with caplog.at_level("WARNING"):
        module = importlib.import_module(MODULE_NAME)

    assert module.AppConfig.DATABASE_URL == "postgresql://localhost/osint_db"
    assert any("DATABASE_URL not set" in message for message in caplog.messages)

    _reset_module()
