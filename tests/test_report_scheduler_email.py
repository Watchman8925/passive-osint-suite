"""Tests for the report scheduler email delivery flow."""

from types import SimpleNamespace

import pytest

import reporting.report_scheduler as scheduler_module
from reporting.reporting_engine import ReportSchedule


class DummyReportingEngine:
    def schedule_report(self, schedule):  # pragma: no cover - not used here
        return schedule.report_id

    async def generate_report(self, schedule):  # pragma: no cover
        return "report.pdf"


class DummySMTP:
    def __init__(self, *args, **kwargs):
        self.calls = []

    async def connect(self):
        self.calls.append("connect")

    async def starttls(self):
        self.calls.append("starttls")

    async def login(self, *args, **kwargs):
        self.calls.append("login")

    async def sendmail(self, *args, **kwargs):
        self.calls.append("sendmail")

    async def quit(self):
        self.calls.append("quit")


@pytest.mark.asyncio
async def test_send_report_email_uses_starttls(tmp_path, monkeypatch):
    created = {}

    def smtp_factory(*args, **kwargs):
        instance = DummySMTP(*args, **kwargs)
        created["instance"] = instance
        return instance

    monkeypatch.setattr(
        scheduler_module,
        "aiosmtplib",
        SimpleNamespace(SMTP=smtp_factory),
    )

    scheduler = scheduler_module.ReportScheduler(DummyReportingEngine())
    scheduler.email_config = {
        "smtp_server": "smtp.test",
        "smtp_port": 587,
        "sender_email": "reports@example.com",
        "sender_password": "secret",
        "use_tls": True,
    }

    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"dummy")
    schedule = ReportSchedule(
        report_id="rep-1",
        name="Weekly report",
        template="executive_summary",
        frequency="weekly",
        recipients=["ops@example.com"],
    )

    await scheduler._send_report_email(str(pdf_path), schedule)

    instance = created["instance"]
    assert "starttls" in instance.calls
    assert instance.calls[0] == "connect"
