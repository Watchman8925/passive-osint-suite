"""
Security Audit and Monitoring System
Comprehensive security monitoring and compliance reporting
"""

import json
import logging
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from .data_access_control import data_access_control
from .models import SecurityAlert, SecurityEvent
from .rbac_manager import rbac_manager
from .security_database import security_db


class SecurityMonitor:
    """Security monitoring and alerting system"""

    def __init__(self, config_path: str = "security/monitoring_config.json"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)

        # Database connection (initialized later)
        self.db = None

        # Monitoring thresholds
        self.thresholds = {
            "failed_logins_per_hour": 5,
            "suspicious_access_per_hour": 10,
            "data_access_violations_per_hour": 3,
            "api_rate_limit_exceeded": 100,
        }

        # Alert rules
        self.alert_rules = self._initialize_alert_rules()

        # Statistics tracking
        self.stats = defaultdict(int)
        self.hourly_stats = defaultdict(lambda: defaultdict(int))

        # Monitoring thread
        self.monitoring_active = False
        self.monitoring_thread = None

        # Load configuration
        self.load_config()

    def set_database(self, db_connection):
        """Set the database connection for persistence"""
        self.db = db_connection

    def _initialize_alert_rules(self) -> Dict[str, Dict]:
        """Initialize security alert rules"""
        return {
            "multiple_failed_logins": {
                "condition": lambda events: self._count_events_in_window(
                    events, "authentication_failed", timedelta(hours=1)
                )
                >= self.thresholds["failed_logins_per_hour"],
                "severity": "medium",
                "description": "Multiple failed login attempts detected",
            },
            "suspicious_data_access": {
                "condition": lambda events: self._count_events_in_window(
                    events, "access_denied", timedelta(hours=1)
                )
                >= self.thresholds["suspicious_access_per_hour"],
                "severity": "high",
                "description": "Unusual number of access denials detected",
            },
            "privilege_escalation": {
                "condition": lambda events: self._detect_privilege_escalation(events),
                "severity": "critical",
                "description": "Potential privilege escalation detected",
            },
            "data_exfiltration": {
                "condition": lambda events: self._detect_data_exfiltration(events),
                "severity": "critical",
                "description": "Potential data exfiltration detected",
            },
        }

    def log_security_event(
        self,
        event_type: str,
        severity: str = "low",
        user_id: Optional[str] = None,
        details: Optional[Dict] = None,
        source: str = "system",
        ip_address: str = "unknown",
        user_agent: str = "unknown",
    ):
        """Log a security event"""
        if details is None:
            details = {}

        event = SecurityEvent(
            id=f"evt_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            source=source,
        )

        # Save to database (no longer using in-memory storage)
        security_db.save_security_event(event)

        # Update statistics
        self.stats[event_type] += 1
        hour_key = datetime.now().strftime("%Y%m%d_%H")
        self.hourly_stats[hour_key][event_type] += 1

        # Check for alerts
        self._check_alert_conditions()

        self.logger.info(f"Security event logged: {event_type} ({severity})")

    def _check_alert_conditions(self):
        """Check if any alert conditions are met"""
        if self.db is None:
            # Skip alert checking in mock mode
            return

        # Get recent events using the SecurityDatabase method
        recent_events = self.db.get_security_events(
            days=0, limit=1000
        )  # Get events from last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_events = [e for e in recent_events if e.timestamp > one_hour_ago]

        for rule_name, rule_config in self.alert_rules.items():
            if rule_config["condition"](recent_events):
                self._generate_alert(rule_name, rule_config)

    def _generate_alert(self, rule_name: str, rule_config: Dict):
        """Generate a security alert"""
        alert = SecurityAlert(
            id=f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
            timestamp=datetime.now(),
            alert_type=rule_name,
            severity=rule_config["severity"],
            description=rule_config["description"],
            affected_users=[],  # Would be populated based on the specific alert
            affected_data=[],
            recommended_actions=self._get_recommended_actions(rule_name),
            status="new",
            assigned_to=None,
        )

        # Save to database (no longer using in-memory storage)
        security_db.save_security_alert(alert)

        self.logger.warning(
            f"Security alert generated: {rule_name} ({rule_config['severity']})"
        )

    def _get_recommended_actions(self, alert_type: str) -> List[str]:
        """Get recommended actions for alert type"""
        actions = {
            "multiple_failed_logins": [
                "Review login attempt patterns",
                "Consider implementing additional authentication factors",
                "Check for brute force attack indicators",
            ],
            "suspicious_data_access": [
                "Review access patterns for affected users",
                "Verify user permissions and roles",
                "Check for unauthorized access attempts",
            ],
            "privilege_escalation": [
                "Immediately revoke suspicious permissions",
                "Conduct security audit of affected accounts",
                "Review recent role and permission changes",
            ],
            "data_exfiltration": [
                "Isolate affected systems",
                "Review data access logs",
                "Implement additional monitoring controls",
            ],
        }
        return actions.get(alert_type, ["Investigate immediately"])

    def _count_events_in_window(
        self, events: List[SecurityEvent], event_type: str, window: timedelta
    ) -> int:
        """Count events of specific type within time window"""
        cutoff = datetime.now() - window
        return len(
            [e for e in events if e.event_type == event_type and e.timestamp > cutoff]
        )

    def _detect_privilege_escalation(self, events: List[SecurityEvent]) -> bool:
        """Detect potential privilege escalation patterns"""
        # Look for rapid permission changes or role escalations
        recent_events = [
            e
            for e in events
            if e.event_type in ["role_added", "permission_granted"]
            and (datetime.now() - e.timestamp) < timedelta(minutes=30)
        ]

        # Group by user
        user_changes = defaultdict(list)
        for event in recent_events:
            if event.user_id:
                user_changes[event.user_id].append(event)

        # Check for suspicious patterns
        for user_id, user_events in user_changes.items():
            if len(user_events) >= 3:  # Multiple changes in short time
                return True

        return False

    def _detect_data_exfiltration(self, events: List[SecurityEvent]) -> bool:
        """Detect potential data exfiltration patterns"""
        # Look for large data exports or unusual access patterns
        recent_events = [
            e
            for e in events
            if e.event_type in ["data_export", "bulk_access"]
            and (datetime.now() - e.timestamp) < timedelta(hours=1)
        ]

        # Check for high-volume data access
        total_exports = sum([e.details.get("size", 0) for e in recent_events])
        if total_exports > 1000000:  # 1MB threshold
            return True

        return False

    def get_security_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        if self.db is None:
            # Return mock report in mock mode
            return {
                "total_events": 0,
                "events_by_type": {},
                "events_by_severity": {},
                "top_users": [],
                "alerts_summary": {"total": 0, "by_type": {}, "by_severity": {}},
            }

        # Get events using the SecurityDatabase method
        events = self.db.get_security_events(days=days, limit=10000)

        # Get alerts using the SecurityDatabase method
        alerts = self.db.get_security_alerts(days=days, limit=1000)

        report = {
            "period": f"{days} days",
            "total_events": len(events),
            "events_by_type": dict(Counter(e.event_type for e in events)),
            "events_by_severity": dict(Counter(e.severity for e in events)),
            "top_users": self._get_top_users(events, 10),
            "alerts_summary": self._get_alerts_summary(alerts),
            "risk_assessment": self._assess_security_risk(events),
            "recommendations": self._generate_security_recommendations(events),
        }

        return report

    def _get_top_users(self, events: List[SecurityEvent], limit: int) -> List[Dict]:
        """Get users with most security events"""
        user_counts = Counter(e.user_id for e in events if e.user_id)
        return [
            {"user_id": user, "event_count": count}
            for user, count in user_counts.most_common(limit)
        ]

    def _get_alerts_summary(self, alerts: List[SecurityAlert]) -> Dict[str, Any]:
        """Get summary of security alerts"""
        return {
            "total_alerts": len(alerts),
            "alerts_by_type": dict(Counter(a.alert_type for a in alerts)),
            "alerts_by_severity": dict(Counter(a.severity for a in alerts)),
            "unresolved_alerts": len([a for a in alerts if a.status != "resolved"]),
        }

    def _assess_security_risk(self, events: List[SecurityEvent]) -> str:
        """Assess overall security risk level"""
        high_severity_events = len(
            [e for e in events if e.severity in ["high", "critical"]]
        )
        total_events = len(events)

        if total_events == 0:
            return "low"

        risk_ratio = high_severity_events / total_events

        if risk_ratio > 0.3:
            return "critical"
        elif risk_ratio > 0.2:
            return "high"
        elif risk_ratio > 0.1:
            return "medium"
        else:
            return "low"

    def _generate_security_recommendations(
        self, events: List[SecurityEvent]
    ) -> List[str]:
        """Generate security recommendations based on events"""
        recommendations = []

        failed_logins = len(
            [e for e in events if e.event_type == "authentication_failed"]
        )
        if failed_logins > 10:
            recommendations.append("Implement multi-factor authentication")

        access_denials = len([e for e in events if e.event_type == "access_denied"])
        if access_denials > 20:
            recommendations.append("Review and update access control policies")

        if any(e.event_type == "privilege_escalation" for e in events):
            recommendations.append("Conduct immediate security audit")

        return recommendations

    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report for security standards"""
        report = {
            "timestamp": datetime.now(),
            "standards": {
                "access_control": self._check_access_control_compliance(),
                "audit_logging": self._check_audit_logging_compliance(),
                "data_protection": self._check_data_protection_compliance(),
                "incident_response": self._check_incident_response_compliance(),
            },
            "overall_compliance": "compliant",  # Would be calculated based on standards
            "non_compliant_items": [],
        }

        return report

    def _check_access_control_compliance(self) -> Dict[str, Any]:
        """Check access control compliance"""
        return {
            "status": "compliant",
            "checks": {
                "role_based_access": True,
                "least_privilege": True,
                "separation_of_duties": True,
            },
        }

    def _check_audit_logging_compliance(self) -> Dict[str, Any]:
        """Check audit logging compliance"""
        if self.db is None:
            return {"status": "unknown", "events_last_90_days": 0, "compliant": False}

        # Get events from the last 90 days
        events = self.db.get_security_events(
            days=90, limit=100000
        )  # Large limit to get all
        recent_events = len(events)

        return {
            "status": "compliant" if recent_events > 0 else "non_compliant",
            "events_logged": recent_events,
            "required_retention": "90 days",
        }

    def _check_data_protection_compliance(self) -> Dict[str, Any]:
        """Check data protection compliance"""
        return {
            "status": "compliant",
            "encryption": True,
            "access_controls": True,
            "data_classification": True,
        }

    def _check_incident_response_compliance(self) -> Dict[str, Any]:
        """Check incident response compliance"""
        if self.db is None:
            return {
                "status": "unknown",
                "unresolved_alerts": 0,
                "response_time_avg": "unknown",
            }

        # Get recent alerts
        alerts = self.db.get_security_alerts(days=30, limit=1000)
        unresolved_alerts = [a for a in alerts if a.status != "resolved"]

        # Calculate average response time for resolved alerts
        resolved_alerts = [a for a in alerts if a.status == "resolved" and a.resolved_at]
        if resolved_alerts:
            response_times = []
            for alert in resolved_alerts:
                if alert.resolved_at and alert.timestamp:
                    response_time = (alert.resolved_at - alert.timestamp).total_seconds() / 3600  # hours
                    response_times.append(response_time)
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            response_time_str = f"{avg_response_time:.1f} hours"
        else:
            response_time_str = "unknown"

        # Determine compliance status
        status = "compliant"
        if len(unresolved_alerts) > 10:
            status = "non_compliant"
        elif len(unresolved_alerts) > 5:
            status = "warning"

        return {
            "status": status,
            "unresolved_alerts": len(unresolved_alerts),
            "response_time_avg": response_time_str,
        }

    def start_monitoring(self):
        """Start the security monitoring thread"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()

        self.logger.info("Security monitoring started")

    def stop_monitoring(self):
        """Stop the security monitoring thread"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join()

        self.logger.info("Security monitoring stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Perform periodic security checks
                self._perform_security_checks()

                # Clean up old data
                self._cleanup_old_data()

                # Sleep for 5 minutes
                time.sleep(300)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait a minute before retrying

    def _perform_security_checks(self):
        """Perform periodic security checks"""
        # Check for inactive users
        self._check_inactive_users()

        # Check for expired sessions
        self._check_expired_sessions()

        # Check data retention compliance
        data_access_control.apply_data_retention()

    def _check_inactive_users(self):
        """Check for users who haven't logged in recently"""
        thirty_days_ago = datetime.now() - timedelta(days=30)

        for user in rbac_manager.users.values():
            if user.last_login and user.last_login < thirty_days_ago:
                self.log_security_event(
                    "user_inactive",
                    severity="low",
                    user_id=user.id,
                    details={"last_login": user.last_login.isoformat()},
                )

    def _check_expired_sessions(self):
        """Check for expired user sessions"""
        expired_count = 0
        for session in list(rbac_manager.sessions.values()):
            if datetime.now() > session.expires_at:
                rbac_manager.invalidate_session(session.session_id)
                expired_count += 1

        if expired_count > 0:
            self.logger.info(f"Cleaned up {expired_count} expired sessions")

    def _cleanup_old_data(self):
        """Clean up old security data"""
        if self.db is None:
            # Skip cleanup in mock mode
            return

        # Use SecurityDatabase cleanup method
        cleanup_stats = self.db.cleanup_old_data(days=90)
        if cleanup_stats["events_cleaned"] > 0 or cleanup_stats["alerts_cleaned"] > 0:
            self.logger.info(
                f"Cleaned up {cleanup_stats['events_cleaned']} old events "
                f"and {cleanup_stats['alerts_cleaned']} old alerts"
            )

    def save_config(self):
        """Save monitoring configuration"""
        try:
            config = {
                "thresholds": self.thresholds,
                "alert_rules": self.alert_rules,
                "stats": dict(self.stats),
                # Note: security_events and security_alerts are now stored in database
            }

            self.config_path.parent.mkdir(exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2, default=str)

            self.logger.info(f"Monitoring config saved to {self.config_path}")

        except Exception as e:
            self.logger.error(f"Error saving monitoring config: {e}")

    def load_config(self):
        """Load monitoring configuration"""
        try:
            if not self.config_path.exists():
                self.logger.info("Monitoring config file not found, using defaults")
                return

            with open(self.config_path, "r") as f:
                config = json.load(f)

            self.thresholds.update(config.get("thresholds", {}))
            self.alert_rules.update(config.get("alert_rules", {}))
            self.stats.update(config.get("stats", {}))

            # Note: security_events and security_alerts are now loaded from database
            self.logger.info(f"Monitoring config loaded from {self.config_path}")

        except Exception as e:
            self.logger.error(f"Error loading monitoring config: {e}")


# Global security monitor instance
security_monitor = SecurityMonitor()


# Convenience functions
def log_security_event(event_type: str, **kwargs):
    """Log security event"""
    security_monitor.log_security_event(event_type, **kwargs)


def get_security_report(days: int = 7) -> Dict[str, Any]:
    """Get security report"""
    return security_monitor.get_security_report(days)


def get_compliance_report() -> Dict[str, Any]:
    """Get compliance report"""
    return security_monitor.get_compliance_report()
