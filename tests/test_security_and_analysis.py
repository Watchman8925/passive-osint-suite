"""Regression tests for security and analysis fixes."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import List

import pytest

from analysis.conspiracy_analyzer import FixedCrossReferenceEngine
from analysis.cross_reference_engine import CrossReferenceEngine
from security.secrets_manager import SecretsManager


@pytest.fixture(autouse=True)
def _test_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure deterministic environment variables for the tests."""

    master_key = base64.urlsafe_b64encode(b"A" * 32)
    monkeypatch.setenv("OSINT_MASTER_KEY", master_key.decode())
    monkeypatch.setenv("OSINT_USE_KEYRING", "false")
    monkeypatch.setenv("OSINT_TEST_MODE", "true")


def test_secrets_manager_round_trip(tmp_path: Path) -> None:
    """Secrets must be stored and retrieved only when encryption succeeds."""

    key_file = tmp_path / "encryption.key"
    secrets_file = tmp_path / "secrets.enc"
    manager = SecretsManager(str(key_file), str(secrets_file))

    assert manager.store_secret("service", "value") is True
    assert manager.get_secret("service") == "value"


def test_secrets_manager_failures_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Persisting secrets should raise an error instead of silently degrading."""

    key_file = tmp_path / "encryption.key"
    secrets_file = tmp_path / "secrets.enc"
    manager = SecretsManager(str(key_file), str(secrets_file))

    def _broken_open(*args: object, **kwargs: object):
        raise OSError("disk full")

    monkeypatch.setattr("builtins.open", _broken_open)

    with pytest.raises(RuntimeError):
        manager.set_secret("service", "value")


@pytest.mark.asyncio
async def test_fixed_cross_reference_engine_delegates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure the fixed engine proxies to the parent implementation."""

    calls: list[tuple[FixedCrossReferenceEngine, str, List[str], str]] = []

    async def _fake_search(
        self: FixedCrossReferenceEngine,
        query: str,
        target_sources: List[str] | None = None,
        search_mode: str = "comprehensive",
    ) -> List[str]:
        calls.append((self, query, target_sources or [], search_mode))
        return ["ok"]

    monkeypatch.setattr(CrossReferenceEngine, "__init__", lambda self: None)
    monkeypatch.setattr(CrossReferenceEngine, "cross_reference_search", _fake_search)

    engine = FixedCrossReferenceEngine()
    result: List[str] = await engine.cross_reference_search(
        "query", target_sources=["source"], search_mode="mode"
    )

    assert result == ["ok"]
    assert calls == [(engine, "query", ["source"], "mode")]
