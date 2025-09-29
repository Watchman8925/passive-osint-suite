"""
Real-time Intelligence Feed System
Continuous monitoring and automated alerts for intelligence changes
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

import aiohttp
import redis.asyncio as redis
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FeedType(Enum):
    """Types of intelligence feeds"""

    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    BREACH = "breach"
    SOCIAL = "social"
    MALWARE = "malware"
    DARKWEB = "darkweb"


@dataclass
class IntelligenceAlert:
    """Real-time intelligence alert"""

    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    feed_type: FeedType
    target: str
    indicators: Dict[str, Any]
    source: str
    confidence: float
    timestamp: datetime
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedSubscription:
    """Subscription to an intelligence feed"""

    subscription_id: str
    feed_type: FeedType
    targets: List[str]
    filters: Dict[str, Any]
    alert_severity_threshold: AlertSeverity
    webhook_url: Optional[str] = None
    email_recipients: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class FeedSource:
    """Intelligence feed source configuration"""

    name: str
    feed_type: FeedType
    url: str
    api_key: Optional[str] = None
    update_interval: int = 300  # seconds
    headers: Dict[str, str] = field(default_factory=dict)
    rate_limit: int = 10  # requests per minute
    enabled: bool = True


class RealTimeIntelligenceFeed:
    """
    Real-time intelligence feed system for continuous monitoring and alerts.
    Monitors various intelligence sources and generates automated alerts.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis = redis.from_url(redis_url)
        self.scheduler = AsyncIOScheduler()
        self.feed_sources: Dict[str, FeedSource] = {}
        self.subscriptions: Dict[str, FeedSubscription] = {}
        self.alert_handlers: List[Callable] = []
        self.last_updates: Dict[str, datetime] = {}

        # Initialize default feed sources
        self._initialize_default_feeds()

    def _initialize_default_feeds(self):
        """Initialize default intelligence feed sources"""
        default_feeds = [
            # IP Intelligence Feeds
            FeedSource(
                name="alienvault_otx",
                feed_type=FeedType.IP,
                url="https://otx.alienvault.com/api/v1/indicators/export",
                update_interval=600,  # 10 minutes
                headers={"Accept": "application/json"},
            ),
            FeedSource(
                name="shodan_alerts",
                feed_type=FeedType.IP,
                url="https://api.shodan.io/shodan/alert",
                update_interval=300,  # 5 minutes
            ),
            FeedSource(
                name="abuseipdb_blacklist",
                feed_type=FeedType.IP,
                url="https://api.abuseipdb.com/api/v2/blacklist",
                update_interval=1800,  # 30 minutes
                headers={"Accept": "application/json", "Key": "{api_key}"},
            ),
            FeedSource(
                name="greynoise_riot",
                feed_type=FeedType.IP,
                url="https://api.greynoise.io/v3/riot",
                update_interval=900,  # 15 minutes
                headers={"Accept": "application/json", "key": "{api_key}"},
            ),
            # Domain Intelligence Feeds
            FeedSource(
                name="certificate_transparency",
                feed_type=FeedType.DOMAIN,
                url="https://crt.sh/",
                update_interval=1800,  # 30 minutes
            ),
            FeedSource(
                name="malware_domains",
                feed_type=FeedType.DOMAIN,
                url="https://malware-domains.com/api/v1/domains/",
                update_interval=900,  # 15 minutes
            ),
            FeedSource(
                name="phishtank_domains",
                feed_type=FeedType.DOMAIN,
                url="http://data.phishtank.com/data/online-valid.json",
                update_interval=3600,  # 1 hour
                headers={"User-Agent": "OSINT-Suite/1.0"},
            ),
            # Breach Intelligence Feeds
            FeedSource(
                name="haveibeenpwned_breaches",
                feed_type=FeedType.BREACH,
                url="https://haveibeenpwned.com/api/v3/breaches",
                update_interval=3600,  # 1 hour
                headers={"User-Agent": "OSINT-Suite/1.0", "hibp-api-key": "{api_key}"},
            ),
            FeedSource(
                name="leakcheck_breaches",
                feed_type=FeedType.BREACH,
                url="https://leakcheck.io/api/v2/query",
                update_interval=1800,  # 30 minutes
            ),
            # Social Media Intelligence Feeds
            FeedSource(
                name="social_scan",
                feed_type=FeedType.SOCIAL,
                url="https://socialscan.robyn.sh/api/search",
                update_interval=7200,  # 2 hours
                headers={"Content-Type": "application/json"},
            ),
            # Malware Intelligence Feeds
            FeedSource(
                name="malwarebazaar_recent",
                feed_type=FeedType.MALWARE,
                url="https://mb-api.abuse.ch/api/v1/",
                update_interval=1800,  # 30 minutes
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            FeedSource(
                name="virustotal_livehunt",
                feed_type=FeedType.MALWARE,
                url="https://www.virustotal.com/api/v3/intelligence/hunting_notifications",
                update_interval=3600,  # 1 hour
                headers={"Accept": "application/json", "x-apikey": "{api_key}"},
            ),
            # Dark Web Intelligence Feeds
            FeedSource(
                name="darkweb_markets",
                feed_type=FeedType.DARKWEB,
                url="https://dark.fail/api/v1/market",
                update_interval=3600,  # 1 hour
                headers={"User-Agent": "OSINT-Suite/1.0"},
            ),
        ]

        for feed in default_feeds:
            self.feed_sources[feed.name] = feed

    async def start_monitoring(self):
        """Start the real-time intelligence monitoring system"""
        logger.info("Starting real-time intelligence feed monitoring...")

        # Start scheduler
        if not self.scheduler.running:
            self.scheduler.start()

        # Schedule feed updates
        for feed_name, feed in self.feed_sources.items():
            if feed.enabled:
                self.scheduler.add_job(
                    self._update_feed,
                    trigger=IntervalTrigger(seconds=feed.update_interval),
                    args=[feed_name],
                    id=f"feed_{feed_name}",
                    name=f"Update {feed_name}",
                    replace_existing=True,
                )
                logger.info(
                    f"Scheduled {feed_name} feed updates every {feed.update_interval}s"
                )

        # Schedule alert processing
        self.scheduler.add_job(
            self._process_alerts,
            trigger=IntervalTrigger(seconds=60),  # Process alerts every minute
            id="process_alerts",
            name="Process Pending Alerts",
            replace_existing=True,
        )

        logger.info("Real-time intelligence monitoring started")

    async def stop_monitoring(self):
        """Stop the monitoring system"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Real-time intelligence monitoring stopped")

    def add_alert_handler(self, handler: Callable):
        """Add an alert handler function"""
        self.alert_handlers.append(handler)

    async def subscribe_to_feed(self, subscription: FeedSubscription) -> str:
        """Subscribe to an intelligence feed"""
        self.subscriptions[subscription.subscription_id] = subscription

        # Store subscription in Redis for persistence
        await self.redis.set(
            f"subscription:{subscription.subscription_id}",
            json.dumps(
                {
                    "subscription_id": subscription.subscription_id,
                    "feed_type": subscription.feed_type.value,
                    "targets": subscription.targets,
                    "filters": subscription.filters,
                    "alert_severity_threshold": subscription.alert_severity_threshold.value,
                    "webhook_url": subscription.webhook_url,
                    "email_recipients": subscription.email_recipients,
                    "enabled": subscription.enabled,
                    "created_at": subscription.created_at.isoformat(),
                }
            ),
        )

        logger.info(
            f"Created subscription {subscription.subscription_id} for {subscription.feed_type.value}"
        )
        return subscription.subscription_id

    async def unsubscribe_from_feed(self, subscription_id: str):
        """Remove a feed subscription"""
        if subscription_id in self.subscriptions:
            del self.subscriptions[subscription_id]
            await self.redis.delete(f"subscription:{subscription_id}")
            logger.info(f"Removed subscription {subscription_id}")

    async def _update_feed(self, feed_name: str):
        """Update intelligence from a specific feed"""
        if feed_name not in self.feed_sources:
            logger.error(f"Unknown feed: {feed_name}")
            return

        feed = self.feed_sources[feed_name]

        try:
            logger.debug(f"Updating feed: {feed_name}")

            # Fetch intelligence from feed
            intelligence_data = await self._fetch_feed_data(feed)

            if intelligence_data:
                # Process and generate alerts
                alerts = await self._process_feed_intelligence(feed, intelligence_data)

                # Store alerts for processing
                for alert in alerts:
                    await self._store_alert(alert)

                logger.info(f"Processed {len(alerts)} alerts from {feed_name}")

        except Exception as e:
            logger.error(f"Failed to update feed {feed_name}: {e}")

    async def _fetch_feed_data(self, feed: FeedSource) -> Optional[Dict[str, Any]]:
        """Fetch data from an intelligence feed"""
        try:
            headers = feed.headers.copy()

            # Add API key if required
            if feed.api_key and "{api_key}" in str(headers):
                for key, value in headers.items():
                    if isinstance(value, str) and "{api_key}" in value:
                        headers[key] = value.replace("{api_key}", feed.api_key)

            # Handle different feed types with appropriate request methods
            async with aiohttp.ClientSession(headers=headers) as session:
                if feed.name == "malwarebazaar_recent":
                    # POST request with form data
                    data = {"query": "get_recent", "selector": "time"}
                    async with session.post(
                        feed.url, data=data, timeout=30
                    ) as response:
                        if response.status == 200:
                            return await response.json()
                elif feed.name == "phishtank_domains":
                    # Simple GET request
                    async with session.get(feed.url, timeout=30) as response:
                        if response.status == 200:
                            return await response.json()
                elif feed.name in ["social_scan", "leakcheck_breaches"]:
                    # These might need special handling or API keys
                    # For now, skip if no API key configured
                    if not feed.api_key:
                        logger.debug(f"Skipping {feed.name} - no API key configured")
                        return None
                    async with session.get(feed.url, timeout=30) as response:
                        if response.status == 200:
                            return await response.json()
                else:
                    # Default GET request
                    async with session.get(feed.url, timeout=30) as response:
                        if response.status == 200:
                            content_type = response.headers.get("content-type", "")
                            if "json" in content_type:
                                return await response.json()
                            else:
                                return {"raw_data": await response.text()}
                        else:
                            logger.warning(
                                f"Feed {feed.name} returned status {response.status}"
                            )
                            return None

        except Exception as e:
            logger.error(f"Failed to fetch data from {feed.name}: {e}")
            return None

    async def _process_feed_intelligence(
        self, feed: FeedSource, data: Dict[str, Any]
    ) -> List[IntelligenceAlert]:
        """Process intelligence data and generate alerts"""
        alerts = []

        try:
            if feed.feed_type == FeedType.IP:
                alerts.extend(await self._process_ip_intelligence(feed, data))
            elif feed.feed_type == FeedType.DOMAIN:
                alerts.extend(await self._process_domain_intelligence(feed, data))
            elif feed.feed_type == FeedType.BREACH:
                alerts.extend(await self._process_breach_intelligence(feed, data))
            elif feed.feed_type == FeedType.MALWARE:
                alerts.extend(await self._process_malware_intelligence(feed, data))
            elif feed.feed_type == FeedType.SOCIAL:
                alerts.extend(await self._process_social_intelligence(feed, data))
            elif feed.feed_type == FeedType.DARKWEB:
                alerts.extend(await self._process_darkweb_intelligence(feed, data))

        except Exception as e:
            logger.error(f"Failed to process intelligence from {feed.name}: {e}")

        return alerts

    async def _process_ip_intelligence(
        self, feed: FeedSource, data: Dict[str, Any]
    ) -> List[IntelligenceAlert]:
        """Process IP address intelligence"""
        alerts = []

        # Example processing for AlienVault OTX
        if "indicators" in data:
            for indicator in data["indicators"]:
                if indicator.get("type") == "IPv4":
                    ip = indicator.get("indicator")
                    if ip:
                        # Check if this IP is in our monitored targets
                        for subscription in self.subscriptions.values():
                            if (
                                subscription.feed_type == FeedType.IP
                                and subscription.enabled
                                and (
                                    not subscription.targets
                                    or ip in subscription.targets
                                )
                            ):

                                alert = IntelligenceAlert(
                                    alert_id=f"ip_alert_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                                    title=f"IP Intelligence Alert: {ip}",
                                    description=f"New intelligence available for IP address {ip}",
                                    severity=AlertSeverity.MEDIUM,
                                    feed_type=FeedType.IP,
                                    target=ip,
                                    indicators={
                                        "ip": ip,
                                        "threat_score": indicator.get(
                                            "threat_score", 0
                                        ),
                                        "pulse_count": indicator.get("pulse_count", 0),
                                    },
                                    source=feed.name,
                                    confidence=0.8,
                                    timestamp=datetime.now(),
                                    tags={"ip", "threat_intelligence"},
                                )
                                alerts.append(alert)

        return alerts

    async def _process_domain_intelligence(
        self, feed: FeedSource, data: Dict[str, Any]
    ) -> List[IntelligenceAlert]:
        """Process domain intelligence"""
        alerts = []

        # Example processing for certificate transparency or malware domains
        domains = []
        if "domains" in data:
            domains = data["domains"]
        elif "raw_data" in data:
            # Parse raw data for domains
            domains = self._extract_domains_from_text(data["raw_data"])

        for domain in domains:
            for subscription in self.subscriptions.values():
                if (
                    subscription.feed_type == FeedType.DOMAIN
                    and subscription.enabled
                    and (
                        not subscription.targets
                        or any(target in domain for target in subscription.targets)
                    )
                ):

                    alert = IntelligenceAlert(
                        alert_id=f"domain_alert_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        title=f"Domain Intelligence Alert: {domain}",
                        description=f"New intelligence available for domain {domain}",
                        severity=(
                            AlertSeverity.HIGH
                            if "malware" in domain
                            else AlertSeverity.MEDIUM
                        ),
                        feed_type=FeedType.DOMAIN,
                        target=domain,
                        indicators={
                            "domain": domain,
                            "discovered_via": feed.name,
                            "risk_level": "high" if "malware" in domain else "medium",
                        },
                        source=feed.name,
                        confidence=0.9,
                        timestamp=datetime.now(),
                        tags={
                            "domain",
                            (
                                "certificate_transparency"
                                if "crt.sh" in feed.url
                                else "malware"
                            ),
                        },
                    )
                    alerts.append(alert)

        return alerts

    async def _process_breach_intelligence(
        self, feed: FeedSource, data: Dict[str, Any]
    ) -> List[IntelligenceAlert]:
        """Process breach intelligence"""
        alerts = []

        if isinstance(data, list):  # HaveIBeenPwned breaches
            for breach in data:
                if not isinstance(breach, dict):
                    continue
                breach_name = breach.get("Name", "")
                breach_date = breach.get("BreachDate", "")

                for subscription in self.subscriptions.values():
                    if (
                        subscription.feed_type == FeedType.BREACH
                        and subscription.enabled
                    ):

                        alert = IntelligenceAlert(
                            alert_id=f"breach_alert_{breach_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                            title=f"New Data Breach: {breach_name}",
                            description=f"New breach discovered: {breach.get('Description', '') if isinstance(breach, dict) else ''}",
                            severity=AlertSeverity.HIGH,
                            feed_type=FeedType.BREACH,
                            target=breach_name,
                            indicators={
                                "breach_name": breach_name,
                                "breach_date": breach_date,
                                "compromised_accounts": breach.get("PwnCount", 0) if isinstance(breach, dict) else 0,
                                "compromised_data": breach.get("DataClasses", []) if isinstance(breach, dict) else [],
                            },
                            source=feed.name,
                            confidence=0.95,
                            timestamp=datetime.now(),
                            tags={"breach", "data_leak"},
                        )
                        alerts.append(alert)

        return alerts

    async def _process_malware_intelligence(
        self, feed: FeedSource, data: Dict[str, Any]
    ) -> List[IntelligenceAlert]:
        """Process malware intelligence"""
        alerts = []

        # Process malware indicators
        indicators = data.get("indicators", [])

        for indicator in indicators:
            indicator_value = indicator.get("value", "")
            indicator_type = indicator.get("type", "")

            for subscription in self.subscriptions.values():
                if subscription.feed_type == FeedType.MALWARE and subscription.enabled:

                    alert = IntelligenceAlert(
                        alert_id=f"malware_alert_{indicator_value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        title=f"Malware Indicator: {indicator_value}",
                        description=f"New malware indicator detected: {indicator_value}",
                        severity=AlertSeverity.CRITICAL,
                        feed_type=FeedType.MALWARE,
                        target=indicator_value,
                        indicators={
                            "indicator": indicator_value,
                            "type": indicator_type,
                            "threat_level": indicator.get("threat_level", "unknown"),
                            "first_seen": indicator.get("first_seen", ""),
                        },
                        source=feed.name,
                        confidence=0.9,
                        timestamp=datetime.now(),
                        tags={"malware", "threat_indicator"},
                    )
                    alerts.append(alert)

        return alerts

    async def _process_social_intelligence(
        self, feed: FeedSource, data: Dict[str, Any]
    ) -> List[IntelligenceAlert]:
        """Process social media intelligence"""
        alerts = []

        # Process social media profiles and mentions
        profiles = data.get("profiles", [])

        for profile in profiles:
            profile_username = profile.get("username", "")
            platform = profile.get("platform", "")

            for subscription in self.subscriptions.values():
                if subscription.feed_type == FeedType.SOCIAL and subscription.enabled:

                    alert = IntelligenceAlert(
                        alert_id=f"social_alert_{platform}_{profile_username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        title=f"Social Media Profile: {profile_username}",
                        description=f"New social media profile discovered on {platform}",
                        severity=AlertSeverity.MEDIUM,
                        feed_type=FeedType.SOCIAL,
                        target=profile_username,
                        indicators={
                            "username": profile_username,
                            "platform": platform,
                            "profile_url": profile.get("url", ""),
                            "is_active": profile.get("is_active", True),
                        },
                        source=feed.name,
                        confidence=0.8,
                        timestamp=datetime.now(),
                        tags={"social", "profile", platform.lower()},
                    )
                    alerts.append(alert)

        return alerts

    async def _process_darkweb_intelligence(
        self, feed: FeedSource, data: Dict[str, Any]
    ) -> List[IntelligenceAlert]:
        """Process dark web intelligence"""
        alerts = []

        # Process dark web market data
        markets = data.get("markets", [])

        for market in markets:
            market_name = market.get("name", "")
            market_url = market.get("url", "")

            for subscription in self.subscriptions.values():
                if subscription.feed_type == FeedType.DARKWEB and subscription.enabled:

                    alert = IntelligenceAlert(
                        alert_id=f"darkweb_alert_{market_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        title=f"Dark Web Market: {market_name}",
                        description=f"Dark web market activity detected: {market_name}",
                        severity=AlertSeverity.HIGH,
                        feed_type=FeedType.DARKWEB,
                        target=market_name,
                        indicators={
                            "market_name": market_name,
                            "market_url": market_url,
                            "status": market.get("status", "unknown"),
                            "last_seen": market.get("last_seen", ""),
                        },
                        source=feed.name,
                        confidence=0.9,
                        timestamp=datetime.now(),
                        tags={"darkweb", "market", "threat"},
                    )
                    alerts.append(alert)

        return alerts

    def _extract_domains_from_text(self, text: str) -> List[str]:
        """Extract domain names from raw text"""
        import re

        # Simple domain extraction regex
        domain_pattern = r"\b([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b"
        domains = re.findall(domain_pattern, text.lower())
        return list(set(domains))  # Remove duplicates

    async def _store_alert(self, alert: IntelligenceAlert):
        """Store alert for processing"""
        alert_data = {
            "alert_id": alert.alert_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "feed_type": alert.feed_type.value,
            "target": alert.target,
            "indicators": alert.indicators,
            "source": alert.source,
            "confidence": alert.confidence,
            "timestamp": alert.timestamp.isoformat(),
            "tags": list(alert.tags),
            "metadata": alert.metadata,
        }

        # Store in Redis
        await self.redis.lpush("pending_alerts", json.dumps(alert_data))
        await self.redis.set(f"alert:{alert.alert_id}", json.dumps(alert_data))

    async def _process_alerts(self):
        """Process pending alerts and send notifications"""
        try:
            # Get pending alerts
            pending_alerts = await self.redis.lrange("pending_alerts", 0, -1)

            for alert_data in pending_alerts:
                alert_dict = json.loads(alert_data)
                alert = IntelligenceAlert(
                    alert_id=alert_dict["alert_id"],
                    title=alert_dict["title"],
                    description=alert_dict["description"],
                    severity=AlertSeverity(alert_dict["severity"]),
                    feed_type=FeedType(alert_dict["feed_type"]),
                    target=alert_dict["target"],
                    indicators=alert_dict["indicators"],
                    source=alert_dict["source"],
                    confidence=alert_dict["confidence"],
                    timestamp=datetime.fromisoformat(alert_dict["timestamp"]),
                    tags=set(alert_dict["tags"]),
                    metadata=alert_dict["metadata"],
                )

                # Process alert through handlers
                await self._handle_alert(alert)

                # Remove from pending queue
                await self.redis.lrem("pending_alerts", 1, alert_data)

        except Exception as e:
            logger.error(f"Failed to process alerts: {e}")

    async def _handle_alert(self, alert: IntelligenceAlert):
        """Handle an intelligence alert"""
        # Call registered alert handlers
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")

        # Send notifications based on subscriptions
        for subscription in self.subscriptions.values():
            if (
                subscription.feed_type == alert.feed_type
                and subscription.enabled
                and alert.severity.value >= subscription.alert_severity_threshold.value
                and (not subscription.targets or alert.target in subscription.targets)
            ):

                # Send webhook notification
                if subscription.webhook_url:
                    await self._send_webhook_notification(subscription, alert)

                # Send email notification
                if subscription.email_recipients:
                    await self._send_email_notification(subscription, alert)

    async def _send_webhook_notification(
        self, subscription: FeedSubscription, alert: IntelligenceAlert
    ):
        """Send alert notification via webhook"""
        try:
            payload = {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.value,
                "feed_type": alert.feed_type.value,
                "target": alert.target,
                "indicators": alert.indicators,
                "source": alert.source,
                "confidence": alert.confidence,
                "timestamp": alert.timestamp.isoformat(),
                "subscription_id": subscription.subscription_id,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    subscription.webhook_url, json=payload, timeout=10
                ) as response:
                    if response.status == 200:
                        logger.info(
                            f"Webhook notification sent for alert {alert.alert_id}"
                        )
                    else:
                        logger.warning(
                            f"Webhook notification failed with status {response.status}"
                        )

        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")

    async def _send_email_notification(
        self, subscription: FeedSubscription, alert: IntelligenceAlert
    ):
        """Send alert notification via email"""
        try:
            # Email sending logic would go here
            # This would integrate with the report scheduler's email functionality
            logger.info(
                f"Email notification would be sent for alert {alert.alert_id} to {len(subscription.email_recipients)} recipients"
            )

        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")

    async def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent intelligence alerts"""
        try:
            # Get alert keys
            alert_keys = await self.redis.keys("alert:*")

            if not alert_keys:
                return []

            # Get alert data
            alerts = []
            for key in alert_keys[:limit]:
                alert_data = await self.redis.get(key)
                if alert_data:
                    alerts.append(json.loads(alert_data))

            # Sort by timestamp (most recent first)
            alerts.sort(key=lambda x: x["timestamp"], reverse=True)

            return alerts

        except Exception as e:
            logger.error(f"Failed to get recent alerts: {e}")
            return []

    async def get_feed_status(self) -> Dict[str, Any]:
        """Get status of all intelligence feeds"""
        status = {}

        for feed_name, feed in self.feed_sources.items():
            last_update = self.last_updates.get(feed_name)
            status[feed_name] = {
                "enabled": feed.enabled,
                "feed_type": feed.feed_type.value,
                "last_update": last_update.isoformat() if last_update else None,
                "update_interval": feed.update_interval,
                "status": "active" if feed.enabled else "disabled",
            }

        return status

    async def enable_feed(self, feed_name: str) -> bool:
        """Enable an intelligence feed"""
        if feed_name in self.feed_sources:
            self.feed_sources[feed_name].enabled = True
            logger.info(f"Enabled feed: {feed_name}")
            return True
        return False

    async def disable_feed(self, feed_name: str) -> bool:
        """Disable an intelligence feed"""
        if feed_name in self.feed_sources:
            self.feed_sources[feed_name].enabled = False
            logger.info(f"Disabled feed: {feed_name}")
            return True
        return False

    async def get_feeds_status(self) -> Dict[str, Any]:
        """Get status of all intelligence feeds (alias for get_feed_status)"""
        return await self.get_feed_status()

    async def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge an intelligence alert"""
        try:
            # Mark alert as acknowledged
            alert_data = await self.redis.get(f"alert:{alert_id}")
            if alert_data:
                alert_dict = json.loads(alert_data)
                alert_dict["acknowledged"] = True
                alert_dict["acknowledged_by"] = user_id
                alert_dict["acknowledged_at"] = datetime.now().isoformat()

                await self.redis.set(f"alert:{alert_id}", json.dumps(alert_dict))
                logger.info(f"Alert {alert_id} acknowledged by {user_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False

    async def subscribe_to_alerts(
        self, user_id: str, alert_types: List[str], notification_channels: List[str]
    ) -> str:
        """Subscribe to specific types of intelligence alerts"""
        import uuid

        subscription_id = f"sub_{user_id}_{uuid.uuid4().hex[:8]}"

        # Convert alert types to FeedType enums
        feed_types = []
        for alert_type in alert_types:
            try:
                if alert_type == "all":
                    feed_types = list(FeedType)
                    break
                feed_types.append(FeedType(alert_type))
            except ValueError:
                logger.warning(f"Unknown alert type: {alert_type}")

        # Create subscriptions for each feed type
        for feed_type in feed_types:
            subscription = FeedSubscription(
                subscription_id=f"{subscription_id}_{feed_type.value}",
                feed_type=feed_type,
                targets=[],  # Monitor all targets
                filters={},
                alert_severity_threshold=AlertSeverity.LOW,
                webhook_url=None,  # WebSocket will be used
                email_recipients=[],
                enabled=True,
            )
            await self.subscribe_to_feed(subscription)

        logger.info(f"Created alert subscription {subscription_id} for user {user_id}")
        return subscription_id

    async def unsubscribe_from_alerts(self, subscription_id: str, user_id: str) -> bool:
        """Unsubscribe from intelligence alerts"""
        try:
            # Find and remove subscriptions with this base ID
            removed = False
            keys_to_remove = []
            async for key in self.redis.scan_iter(f"subscription:{subscription_id}*"):
                keys_to_remove.append(key)

            for key in keys_to_remove:
                sub_id = key.decode().split(":", 1)[1]
                await self.unsubscribe_from_feed(sub_id)
                removed = True

            if removed:
                logger.info(
                    f"Removed alert subscription {subscription_id} for user {user_id}"
                )
            return removed
        except Exception as e:
            logger.error(f"Failed to unsubscribe from alerts {subscription_id}: {e}")
            return False

    async def get_feed_sources(self) -> List[Dict[str, Any]]:
        """Get information about available intelligence feed sources"""
        sources = []
        for feed_name, feed in self.feed_sources.items():
            sources.append(
                {
                    "name": feed.name,
                    "feed_type": feed.feed_type.value,
                    "url": feed.url,
                    "update_interval": feed.update_interval,
                    "enabled": feed.enabled,
                    "rate_limit": feed.rate_limit,
                    "requires_api_key": feed.api_key is not None,
                }
            )
        return sources

    async def configure_feed_api_key(self, feed_name: str, api_key: str) -> bool:
        """Configure API key for a specific feed"""
        if feed_name in self.feed_sources:
            self.feed_sources[feed_name].api_key = api_key
            logger.info(f"Configured API key for feed: {feed_name}")
            return True
        return False

    async def add_custom_feed(self, feed: FeedSource) -> bool:
        """Add a custom intelligence feed source"""
        if feed.name in self.feed_sources:
            logger.warning(f"Feed {feed.name} already exists")
            return False

        self.feed_sources[feed.name] = feed
        logger.info(f"Added custom feed: {feed.name}")

        # If monitoring is active, schedule the new feed
        if hasattr(self, "scheduler") and self.scheduler.running:
            self.scheduler.add_job(
                self._update_feed,
                trigger=IntervalTrigger(seconds=feed.update_interval),
                args=[feed.name],
                id=f"feed_{feed.name}",
                name=f"Update {feed.name}",
                replace_existing=True,
            )

        return True

    async def remove_feed(self, feed_name: str) -> bool:
        """Remove an intelligence feed source"""
        if feed_name in self.feed_sources:
            # Remove from scheduler if active
            if hasattr(self, "scheduler") and self.scheduler.running:
                try:
                    self.scheduler.remove_job(f"feed_{feed_name}")
                except Exception:
                    pass  # Job might not exist

            del self.feed_sources[feed_name]
            logger.info(f"Removed feed: {feed_name}")
            return True
        return False

    async def test_feed_connection(self, feed_name: str) -> Dict[str, Any]:
        """Test connection to a specific intelligence feed"""
        if feed_name not in self.feed_sources:
            return {"success": False, "error": "Feed not found"}

        feed = self.feed_sources[feed_name]

        try:
            # Attempt to fetch data from the feed
            data = await self._fetch_feed_data(feed)

            if data is not None:
                return {
                    "success": True,
                    "feed_name": feed_name,
                    "response_time": "N/A",  # Could be measured
                    "data_sample": (
                        str(data)[:200] + "..." if len(str(data)) > 200 else str(data)
                    ),
                }
            else:
                return {
                    "success": False,
                    "feed_name": feed_name,
                    "error": "No data received",
                }
        except Exception as e:
            return {"success": False, "feed_name": feed_name, "error": str(e)}
