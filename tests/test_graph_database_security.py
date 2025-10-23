"""Tests for secure Neo4j password handling."""

from __future__ import annotations

import pytest

import database.graph_database as graph_module


@pytest.fixture(autouse=True)
def _enable_dummy_neo4j(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure the adapter behaves as if the Neo4j driver is available."""

    monkeypatch.setattr(graph_module, "NEO4J_AVAILABLE", True)

    # The adapter only stores the password at init time, so we can use simple stubs.
    class _DummyDriver:  # pragma: no cover - helper for completeness
        async def verify_connectivity(self) -> None:
            return None

        async def close(self) -> None:
            return None

    class _DummyGraphDatabase:  # pragma: no cover - helper for completeness
        @staticmethod
        def driver(*args, **kwargs):
            return _DummyDriver()

    monkeypatch.setattr(graph_module, "AsyncGraphDatabase", _DummyGraphDatabase)
    monkeypatch.setattr(graph_module, "AsyncDriver", _DummyDriver)


def test_graph_adapter_rejects_insecure_password() -> None:
    with pytest.raises(ValueError):
        graph_module.GraphDatabaseAdapter(password="password")


def test_graph_adapter_accepts_secure_password() -> None:
    adapter = graph_module.GraphDatabaseAdapter(password="s3cure-test-password")
    assert adapter.password == "s3cure-test-password"
