#!/usr/bin/env python3
"""Tests for the real-time intelligence feed integration."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from realtime.realtime_feeds import RealTimeIntelligenceFeed


class _FakeRedis:
    """Minimal async Redis stub used to exercise feed read operations."""

    def __init__(self, alerts: dict[str, dict[str, str]]) -> None:
        self._alerts = {key: json.dumps(value) for key, value in alerts.items()}

    async def keys(self, pattern: str) -> list[str]:
        if pattern != "alert:*":
            return []
        return list(self._alerts.keys())

    async def get(self, key: str) -> str | None:
        return self._alerts.get(key)


@pytest.fixture()
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> _FakeRedis:
    """Provide a fake Redis client for the feed under test."""

    alerts: dict[str, dict[str, str]] = {
        "alert:1": {
            "alert_id": "alert:1",
            "title": "Credential leak detected",
            "timestamp": datetime(2024, 1, 1, tzinfo=timezone.utc).isoformat(),
        },
        "alert:2": {
            "alert_id": "alert:2",
            "title": "Suspicious domain registered",
            "timestamp": datetime(2024, 2, 1, tzinfo=timezone.utc).isoformat(),
        },
    }

    fake_client = _FakeRedis(alerts)
    monkeypatch.setattr(
        "realtime.realtime_feeds.redis.from_url",
        lambda redis_url: fake_client,
    )
    return fake_client


def _run(coro: Awaitable[object]) -> object:
    """Execute an async coroutine without requiring pytest-asyncio."""

    return asyncio.run(coro)


def test_realtime_feeds_read_operations(fake_redis: _FakeRedis) -> None:
    """Ensure status, alerts, and source metadata can be retrieved."""

    feed = RealTimeIntelligenceFeed(redis_url="redis://example")

    async def _exercise() -> None:
        status = await feed.get_feeds_status()
        assert status, "Expected default feed status entries to be returned"

        alerts = await feed.get_recent_alerts(limit=5)
        assert [alert["alert_id"] for alert in alerts] == [
            "alert:2",
            "alert:1",
        ], "Alerts should be returned in reverse chronological order"

        sources = await feed.get_feed_sources()
        assert sources, "Expected at least one feed source configuration"
        assert all("name" in source and "feed_type" in source for source in sources)

    _run(_exercise())
