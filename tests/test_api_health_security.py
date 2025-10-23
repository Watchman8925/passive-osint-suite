"""Regression tests for the API health endpoints requiring authentication."""

import os
import sys
from datetime import datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

# Ensure the repository root is importable when running tests directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture()
def api_module(monkeypatch):
    """Provide the API module with a deterministic secret configuration."""

    monkeypatch.setenv(
        "OSINT_SECRET_KEY",
        "health-check-secret-key-with-minimum-length-123",
    )
    monkeypatch.setenv("OSINT_TEST_MODE", "true")
    monkeypatch.setenv("OSINT_USE_KEYRING", "false")
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/osint_db")
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("NEO4J_PASSWORD", "test-secure-password-123")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    import api.api_server as api_server

    monkeypatch.setattr(
        api_server.AppConfig,
        "SECRET_KEY",
        "health-check-secret-key-with-minimum-length-123",
        raising=False,
    )

    return api_server


@pytest.fixture()
def client(api_module):
    """Provide a TestClient using the configured API module."""

    with TestClient(api_module.app) as test_client:
        yield test_client


def _auth_headers(api_module, subject: str = "health-checker") -> dict[str, str]:
    """Generate a valid JWT for the provided subject."""

    payload = {
        "sub": subject,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
    }
    token = jwt.encode(payload, api_module.AppConfig.SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return {"Authorization": f"Bearer {token}"}


def test_health_endpoint_rejects_missing_token(client):
    response = client.get("/api/health")
    assert response.status_code == 401


def test_health_endpoint_allows_authenticated_access(api_module, client):
    headers = _auth_headers(api_module)
    response = client.get("/api/health", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["requested_by"] == "health-checker"


def test_health_alias_requires_token(api_module, client):
    # Verify /health rejects unauthenticated access
    response = client.get("/health")
    assert response.status_code == 401

    # With a valid token the alias should forward to the primary endpoint
    headers = _auth_headers(api_module, subject="alias-tester")
    response = client.get("/health", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["requested_by"] == "alias-tester"


def test_detailed_health_reports_requester(api_module, client):
    headers = _auth_headers(api_module, subject="detailed-user")
    response = client.get("/api/health/detailed", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["requested_by"] == "detailed-user"
