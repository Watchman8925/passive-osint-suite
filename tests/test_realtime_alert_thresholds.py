"""Tests for severity threshold handling in the realtime feeds."""

from datetime import datetime
from typing import List

import pytest

import realtime.realtime_feeds as feeds_module
from realtime.realtime_feeds import (
    AlertSeverity,
    FeedSubscription,
    FeedType,
    IntelligenceAlert,
    RealTimeIntelligenceFeed,
)


class DummyRedis:
    async def lrange(self, *args, **kwargs):
        return []

    async def lrem(self, *args, **kwargs):
        return 0


@pytest.mark.asyncio
async def test_medium_alert_below_high_threshold(monkeypatch):
    monkeypatch.setattr(feeds_module.redis, "from_url", lambda url: DummyRedis())
    feed = RealTimeIntelligenceFeed()
    feed.subscriptions = {
        "sub": FeedSubscription(
            subscription_id="sub",
            feed_type=FeedType.DOMAIN,
            targets=[],
            filters={},
            alert_severity_threshold=AlertSeverity.HIGH,
            webhook_url=None,
            email_recipients=[],
        )
    }

    notifications: List[str] = []

    async def fake_webhook(subscription, alert):
        notifications.append("webhook")

    async def fake_email(subscription, alert):
        notifications.append("email")

    monkeypatch.setattr(feed, "_send_webhook_notification", fake_webhook)
    monkeypatch.setattr(feed, "_send_email_notification", fake_email)

    alert = IntelligenceAlert(
        alert_id="a1",
        title="Medium alert",
        description="",
        severity=AlertSeverity.MEDIUM,
        feed_type=FeedType.DOMAIN,
        target="example.com",
        indicators={},
        source="test",
        confidence=0.5,
        timestamp=datetime.utcnow(),
        tags=set(),
        metadata={},
    )

    await feed._handle_alert(alert)

    assert notifications == []


@pytest.mark.asyncio
async def test_critical_alert_exceeds_high_threshold(monkeypatch):
    monkeypatch.setattr(feeds_module.redis, "from_url", lambda url: DummyRedis())
    feed = RealTimeIntelligenceFeed()
    feed.subscriptions = {
        "sub": FeedSubscription(
            subscription_id="sub",
            feed_type=FeedType.DOMAIN,
            targets=[],
            filters={},
            alert_severity_threshold=AlertSeverity.HIGH,
            webhook_url=None,
            email_recipients=["ops@example.com"],
        )
    }

    notifications: List[str] = []

    async def fake_webhook(subscription, alert):
        notifications.append("webhook")

    async def fake_email(subscription, alert):
        notifications.append("email")

    monkeypatch.setattr(feed, "_send_webhook_notification", fake_webhook)
    monkeypatch.setattr(feed, "_send_email_notification", fake_email)

    alert = IntelligenceAlert(
        alert_id="a2",
        title="Critical alert",
        description="",
        severity=AlertSeverity.CRITICAL,
        feed_type=FeedType.DOMAIN,
        target="example.com",
        indicators={},
        source="test",
        confidence=0.9,
        timestamp=datetime.utcnow(),
        tags=set(),
        metadata={},
    )

    await feed._handle_alert(alert)

    assert notifications == ["email"]
