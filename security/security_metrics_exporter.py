#!/usr/bin/env python3
"""
Security Metrics Exporter for Prometheus
Exposes security framework metrics for monitoring
"""

import logging
import time

from prometheus_client import Counter, Gauge, Histogram, start_http_server

from security.rbac_manager import rbac_manager
from security.security_monitor import security_monitor


class SecurityMetricsExporter:
    """Prometheus metrics exporter for security framework"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Security Event Metrics
        self.security_events_total = Counter(
            "osint_security_events_total",
            "Total number of security events",
            ["event_type", "severity"],
        )

        self.authentication_attempts = Counter(
            "osint_authentication_attempts_total",
            "Total authentication attempts",
            ["result"],
        )

        self.active_sessions = Gauge(
            "osint_active_sessions", "Number of active user sessions"
        )

        self.security_alerts = Gauge(
            "osint_security_alerts",
            "Number of active security alerts",
            ["severity", "status"],
        )

        # Data Access Metrics
        self.data_access_total = Counter(
            "osint_data_access_total",
            "Total data access operations",
            ["classification", "action", "result"],
        )

        # Performance Metrics
        self.request_duration = Histogram(
            "osint_security_request_duration_seconds",
            "Security operation duration",
            ["operation"],
        )

        # Compliance Metrics
        self.compliance_score = Gauge(
            "osint_security_compliance_score", "Security compliance score (0-100)"
        )

    def collect_metrics(self):
        """Collect metrics from security components"""
        try:
            # Get security report for metrics
            report = security_monitor.get_security_report(days=1)

            # Update event metrics
            for event_type, count in report.get("events_by_type", {}).items():
                severity = "info"  # Default severity
                self.security_events_total.labels(
                    event_type=event_type, severity=severity
                ).inc(count)

            # Update session metrics
            if hasattr(rbac_manager, "sessions"):
                self.active_sessions.set(len(rbac_manager.sessions))

            # Update alert metrics
            alerts_summary = report.get("alerts_summary", {})
            self.security_alerts.labels(severity="high", status="active").set(
                alerts_summary.get("unresolved_alerts", 0)
            )

            # Update compliance score based on risk assessment
            risk_assessment = report.get("risk_assessment", "low")
            compliance_map = {"low": 95, "medium": 85, "high": 75, "critical": 60}
            self.compliance_score.set(compliance_map.get(risk_assessment, 80))

            self.logger.debug("Security metrics collected successfully")

        except Exception as e:
            self.logger.error(f"Failed to collect security metrics: {e}")


def main():
    """Start the metrics exporter"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Initialize metrics exporter
    exporter = SecurityMetricsExporter()

    # Start Prometheus HTTP server
    port = 8001
    start_http_server(port)
    logger.info(f"Security metrics exporter started on port {port}")

    # Collect metrics every 30 seconds
    while True:
        exporter.collect_metrics()
        time.sleep(30)


if __name__ == "__main__":
    main()
