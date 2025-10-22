from __future__ import annotations

import logging
from typing import Dict

import jwt

import health_check


def test_generate_api_token_encodes_subject() -> None:
    """The generated token should embed the requested subject."""

    secret = "super-secret"
    token = health_check.generate_api_token(secret, subject="ci", ttl_seconds=120)
    payload = jwt.decode(token, secret, algorithms=["HS256"])

    assert payload["sub"] == "ci"
    assert payload["exp"] > payload["iat"]


def test_main_runs_api_health_check(monkeypatch) -> None:
    """Running the CLI with an API URL should invoke the authenticated check."""

    captured: Dict[str, object] = {}

    class DummyChecker(health_check.HealthChecker):
        def __init__(self) -> None:
            super().__init__()
            captured["checker"] = self

        def run_all_checks(self):  # type: ignore[override]
            self._add_check_result("baseline", "pass", "baseline ok")
            self._determine_overall_status()
            self._generate_recommendations()
            return self.results

        def print_report(self) -> None:  # type: ignore[override]
            captured["printed"] = True

        def save_report(self, filename: str = "health_report.json") -> None:  # type: ignore[override]
            captured["saved_path"] = filename

    monkeypatch.setattr(health_check, "HealthChecker", DummyChecker)

    def fake_generate(
        secret: str, *, subject: str = "health-check", ttl_seconds: int = 600
    ) -> str:
        captured["token_secret"] = secret
        captured["token_subject"] = subject
        captured["token_ttl"] = ttl_seconds
        return "fake-token"

    def fake_run(url: str, token: str, *, timeout: float = 5.0) -> Dict[str, str]:
        captured["api_url"] = url
        captured["api_token"] = token
        captured["api_timeout"] = timeout
        return {"status": "ok", "detail": "alive"}

    monkeypatch.setattr(health_check, "generate_api_token", fake_generate)
    monkeypatch.setattr(health_check, "run_api_health_check", fake_run)

    exit_code = health_check.main(
        [
            "--api-url",
            "http://localhost:8000/api/health",
            "--secret",
            "from-cli",
            "--token-ttl",
            "120",
            "--request-timeout",
            "3.5",
            "--no-save",
            "--quiet",
        ]
    )

    assert exit_code == 0
    checker = captured["checker"]
    assert isinstance(checker, health_check.HealthChecker)
    api_health = checker.results["checks"]["api_health"]
    assert api_health["status"] == "pass"
    assert api_health["details"] == {"status": "ok", "detail": "alive"}
    assert captured["token_secret"] == "from-cli"
    assert captured["token_subject"] == "health-check-cli"
    assert captured["token_ttl"] == 120
    assert captured["api_timeout"] == 3.5
    assert "printed" not in captured
    assert "saved_path" not in captured


def test_api_health_check_skipped_without_secret(monkeypatch, caplog) -> None:
    """If no secret is available, the API health check is skipped with a warning."""

    instances = []

    class DummyChecker(health_check.HealthChecker):
        def __init__(self) -> None:
            super().__init__()
            instances.append(self)

        def run_all_checks(self):  # type: ignore[override]
            self._add_check_result("baseline", "pass", "baseline ok")
            self._determine_overall_status()
            self._generate_recommendations()
            return self.results

        def print_report(self) -> None:  # type: ignore[override]
            pass

        def save_report(self, filename: str = "health_report.json") -> None:  # type: ignore[override]
            pass

    monkeypatch.setattr(health_check, "HealthChecker", DummyChecker)
    monkeypatch.delenv("OSINT_SECRET_KEY", raising=False)

    with caplog.at_level(logging.WARNING, logger="health_check"):
        exit_code = health_check.main(
            ["--api-url", "http://example.com/api/health", "--no-save", "--quiet"]
        )

    assert exit_code == 1
    assert instances, "HealthChecker should have been instantiated"
    api_health = instances[0].results["checks"]["api_health"]
    assert api_health["status"] == "warning"
    assert "skipping authenticated API health check" in api_health["message"]
    assert any(
        "skipping authenticated API health check" in record.message
        for record in caplog.records
    )
