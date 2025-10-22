#!/usr/bin/env python3
"""
Test script for real-time intelligence feeds integration
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from realtime.realtime_feeds import RealTimeIntelligenceFeed


def _run(coro):
    """Execute an async coroutine without requiring pytest-asyncio."""

    return asyncio.run(coro)


def test_realtime_feeds():
    """Test the real-time intelligence feeds functionality"""

    feeds = RealTimeIntelligenceFeed(redis_url="redis://localhost:6379/0")

    async def _run_checks():
        print("🧪 Testing Real-Time Intelligence Feeds...")

        status = await feeds.get_feeds_status()
        print(f"✅ Feed status retrieved: {len(status)} feeds configured")

        alerts = await feeds.get_recent_alerts(10)
        print(f"✅ Recent alerts retrieved: {len(alerts)} alerts")

        sources = await feeds.get_feed_sources()
        print(f"✅ Feed sources retrieved: {len(sources)} sources")

        print("✅ All real-time feeds tests passed!")

    _run(_run_checks())


if __name__ == "__main__":
    pytest.main([__file__])
