#!/usr/bin/env python3
"""
Test script for real-time intelligence feeds integration
"""

import asyncio
import sys

sys.path.insert(0, "/workspaces/passive_osint_suite")

from realtime_feeds import RealTimeIntelligenceFeed


async def test_realtime_feeds():
    """Test the real-time intelligence feeds functionality"""
    print("🧪 Testing Real-Time Intelligence Feeds...")

    # Initialize feeds with mock Redis URL (won't connect but won't fail)
    feeds = RealTimeIntelligenceFeed("redis://localhost:6379")

    # Test feed status
    status = await feeds.get_feeds_status()
    print(f"✅ Feed status retrieved: {len(status)} feeds configured")

    # Test alert retrieval
    alerts = await feeds.get_recent_alerts(10)
    print(f"✅ Recent alerts retrieved: {len(alerts)} alerts")

    # Test feed sources
    sources = await feeds.get_feed_sources()
    print(f"✅ Feed sources retrieved: {len(sources)} sources")

    print("✅ All real-time feeds tests passed!")


if __name__ == "__main__":
    asyncio.run(test_realtime_feeds())
