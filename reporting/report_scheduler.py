"""
Automated Report Scheduler
Handles scheduling and automated generation of intelligence reports
"""

import logging
import os
from datetime import datetime, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List

import aiosmtplib
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from .reporting_engine import EnhancedReportingEngine, ReportSchedule

logger = logging.getLogger(__name__)


class ReportScheduler:
    """Automated report scheduling and delivery service"""

    def __init__(self, reporting_engine: EnhancedReportingEngine):
        self.reporting_engine = reporting_engine
        self.scheduler = AsyncIOScheduler()
        self.email_config = self._load_email_config()
        self.active_schedules: Dict[str, str] = {}  # schedule_id -> job_id

    def _load_email_config(self) -> Dict[str, str]:
        """Load email configuration from environment"""
        return {
            "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            "smtp_port": int(os.getenv("SMTP_PORT", "587")),
            "sender_email": os.getenv("REPORT_EMAIL", "reports@osint-suite.local"),
            "sender_password": os.getenv("REPORT_EMAIL_PASSWORD", ""),
            "use_tls": os.getenv("SMTP_USE_TLS", "true").lower() == "true",
        }

    async def schedule_report(self, schedule: ReportSchedule) -> str:
        """Schedule a recurring report"""
        # Add to reporting engine
        schedule_id = self.reporting_engine.schedule_report(schedule)

        # Create APScheduler job
        job_id = await self._create_scheduler_job(schedule)
        self.active_schedules[schedule_id] = job_id

        logger.info(f"Scheduled report {schedule_id} with job ID {job_id}")
        return schedule_id

    async def _create_scheduler_job(self, schedule: ReportSchedule) -> str:
        """Create APScheduler job for the schedule"""
        if schedule.frequency == "daily":
            # Run daily at 9 AM
            trigger = CronTrigger(hour=9, minute=0)
        elif schedule.frequency == "weekly":
            # Run weekly on Monday at 9 AM
            trigger = CronTrigger(day_of_week="mon", hour=9, minute=0)
        elif schedule.frequency == "monthly":
            # Run monthly on the 1st at 9 AM
            trigger = CronTrigger(day=1, hour=9, minute=0)
        else:
            raise ValueError(f"Unsupported frequency: {schedule.frequency}")

        # Create job
        job = self.scheduler.add_job(
            self._execute_scheduled_report,
            trigger=trigger,
            args=[schedule],
            id=f"report_{schedule.report_id}",
            name=f"Scheduled Report: {schedule.name}",
            replace_existing=True,
        )

        return job.id

    async def _execute_scheduled_report(self, schedule: ReportSchedule):
        """Execute a scheduled report"""
        try:
            logger.info(f"Executing scheduled report: {schedule.name}")

            # Generate mock investigation data (in real implementation, this would fetch from database)
            investigation_data = self._generate_mock_investigation_data(schedule)

            # Generate report
            if schedule.template == "executive_summary":
                report_data = self.reporting_engine.generate_executive_summary(
                    investigation_data
                )
            else:
                report_data = {
                    "investigation_id": f"scheduled_{schedule.report_id}_{datetime.now().strftime('%Y%m%d')}",
                    "generated_at": datetime.now().isoformat(),
                    "title": schedule.name,
                    "executive_summary": f"Scheduled {schedule.frequency} intelligence report",
                    "key_findings": [
                        "Automated intelligence gathering",
                        "Scheduled analysis delivery",
                    ],
                    "recommendations": [
                        "Review report contents",
                        "Take appropriate security actions",
                    ],
                }

            # Generate PDF
            pdf_filename = (
                f"{schedule.template}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            pdf_path = self.reporting_engine.generate_pdf_report(
                report_data, template_name=schedule.template, filename=pdf_filename
            )

            # Send email
            if schedule.recipients:
                await self._send_report_email(pdf_path, schedule)

            logger.info(f"Successfully executed scheduled report: {schedule.name}")

        except Exception as e:
            logger.error(f"Failed to execute scheduled report {schedule.name}: {e}")

    def _generate_mock_investigation_data(self, schedule: ReportSchedule) -> Dict:
        """Generate mock investigation data for scheduled reports"""
        # In a real implementation, this would fetch actual investigation data
        # based on the schedule filters and date ranges
        return {
            "investigation_id": f"scheduled_{schedule.report_id}",
            "targets": schedule.filters.get("targets", ["example.com"]),
            "domain_data": {
                "subdomains_found": 15,
                "recent_registrations": False,
                "suspicious_patterns": ["suspicious-domain-pattern"],
            },
            "ip_data": {
                "blacklisted_ips": 2,
                "geographic_distribution": {"US": 5, "EU": 3},
                "cloud_providers": ["AWS", "Azure"],
            },
            "breach_data": {
                "total_breaches": 3,
                "recent_breaches": [{"date": "2024-01-15", "source": "Example Breach"}],
            },
            "social_data": {"total_profiles": 8, "recent_activity": True},
        }

    async def _send_report_email(self, pdf_path: str, schedule: ReportSchedule):
        """Send report via email"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg["From"] = self.email_config["sender_email"]
            msg["To"] = ", ".join(schedule.recipients)
            msg["Subject"] = (
                f"OSINT Report: {schedule.name} - {datetime.now().strftime('%Y-%m-%d')}"
            )

            # Email body
            body = f"""
            <html>
            <body>
                <h2>Scheduled OSINT Intelligence Report</h2>
                <p>A new {schedule.frequency} intelligence report has been generated.</p>

                <h3>Report Details:</h3>
                <ul>
                    <li><strong>Report:</strong> {schedule.name}</li>
                    <li><strong>Template:</strong> {schedule.template.replace('_', ' ').title()}</li>
                    <li><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                    <li><strong>Frequency:</strong> {schedule.frequency.capitalize()}</li>
                </ul>

                <p>Please find the detailed intelligence report attached.</p>

                <hr>
                <p style="color: #666; font-size: 12px;">
                    This is an automated report from the OSINT Suite.<br>
                    For questions or concerns, please contact your security team.
                </p>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, "html"))

            # Attach PDF
            with open(pdf_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename={os.path.basename(pdf_path)}",
                )
                msg.attach(part)

            # Send email
            if self.email_config["use_tls"]:
                server = aiosmtplib.SMTP(
                    hostname=self.email_config["smtp_server"],
                    port=self.email_config["smtp_port"],
                    use_tls=True,
                )
            else:
                server = aiosmtplib.SMTP(
                    hostname=self.email_config["smtp_server"],
                    port=self.email_config["smtp_port"],
                )

            await server.connect()
            await server.login(
                self.email_config["sender_email"], self.email_config["sender_password"]
            )
            await server.sendmail(
                self.email_config["sender_email"], schedule.recipients, msg.as_string()
            )
            await server.quit()

            logger.info(
                f"Email sent successfully to {len(schedule.recipients)} recipients"
            )

        except Exception as e:
            logger.error(f"Failed to send report email: {e}")
            raise

    async def start_scheduler(self):
        """Start the report scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Report scheduler started")

    async def stop_scheduler(self):
        """Stop the report scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Report scheduler stopped")

    def remove_schedule(self, schedule_id: str):
        """Remove a scheduled report"""
        if schedule_id in self.active_schedules:
            job_id = self.active_schedules[schedule_id]
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
            del self.active_schedules[schedule_id]
            logger.info(f"Removed scheduled report: {schedule_id}")

    def get_active_schedules(self) -> List[Dict]:
        """Get list of active scheduled reports"""
        schedules = []
        for schedule_id, job_id in self.active_schedules.items():
            job = self.scheduler.get_job(job_id)
            if job and schedule_id in self.reporting_engine.schedules:
                schedule = self.reporting_engine.schedules[schedule_id]
                schedules.append(
                    {
                        "schedule_id": schedule_id,
                        "name": schedule.name,
                        "frequency": schedule.frequency,
                        "next_run": (
                            schedule.next_run.isoformat() if schedule.next_run else None
                        ),
                        "recipients": len(schedule.recipients),
                        "enabled": schedule.enabled,
                    }
                )

        return schedules

    async def execute_all_due_reports(self):
        """Manually execute all reports that are due (for testing)"""
        executed = []

        for schedule_id, schedule in self.reporting_engine.schedules.items():
            if (
                schedule.enabled
                and schedule.next_run
                and datetime.now() >= schedule.next_run
            ):
                await self._execute_scheduled_report(schedule)
                executed.append(schedule_id)

                # Update next run time
                if schedule.frequency == "daily":
                    schedule.next_run = schedule.next_run + timedelta(days=1)
                elif schedule.frequency == "weekly":
                    schedule.next_run = schedule.next_run + timedelta(weeks=1)
                elif schedule.frequency == "monthly":
                    next_month = schedule.next_run.replace(day=1) + timedelta(days=32)
                    schedule.next_run = next_month.replace(day=1)

        return executed
