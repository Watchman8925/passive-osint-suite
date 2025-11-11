"""Tests for authentication on Tor control endpoints."""

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def api_app():
    os.environ.setdefault("OSINT_SECRET_KEY", "test-secret")
    os.environ.setdefault("OSINT_TEST_MODE", "true")
    os.environ.setdefault("OSINT_USE_KEYRING", "false")
    from api.api_server import app

    return app


def test_tor_status_requires_auth(api_app):
    client = TestClient(api_app)
    response = client.get("/tor/status")
    assert response.status_code == 401


def test_tor_control_requires_auth(api_app):
    client = TestClient(api_app)
    response = client.post("/api/anonymity/tor/disable")
    assert response.status_code == 401
