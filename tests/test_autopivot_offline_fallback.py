import asyncio
import importlib
import os
import sys
from datetime import datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

# Ensure deterministic configuration before importing the API server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["OSINT_SECRET_KEY"] = "offline-test-secret-key-with-sufficient-length-123"
os.environ.pop("SECRET_KEY", None)
os.environ.pop("PERPLEXITY_API_KEY", None)
os.environ.setdefault("DATABASE_URL", "postgresql://localhost/osint_db")
os.environ.setdefault("ENVIRONMENT", "development")

import api.api_server as api_server  # noqa: E402

# Reload the module to make sure environment updates are applied consistently
api_server = importlib.reload(api_server)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Provide a TestClient with isolated investigation storage."""

    original_store_cls = api_server.PersistentInvestigationStore

    class TempStore(original_store_cls):  # type: ignore[misc]
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("storage_dir", str(tmp_path / "store"))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(api_server, "PersistentInvestigationStore", TempStore)

    # Ensure each test starts without a cached fallback engine
    if hasattr(api_server.app.state, "_autopivot_engine"):
        delattr(api_server.app.state, "_autopivot_engine")

    with TestClient(api_server.app) as test_client:
        yield test_client


def _auth_headers() -> dict:
    """Generate a valid bearer token for the test user."""

    payload = {
        "sub": "test-user",
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
    }
    token = jwt.encode(payload, api_server.AppConfig.SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return {"Authorization": f"Bearer {token}"}


async def _seed_investigation(store, owner_id: str) -> str:
    investigation_id = await store.create_investigation(
        name="Offline Autopivot Test",
        description="Testing fallback autopivot suggestions",
        targets=["example.com"],
        investigation_type="domain",
        priority="medium",
        tags=["offline", "autopivot"],
        owner_id=owner_id,
        scheduled_start=None,
        auto_reporting=False,
    )

    await store.store_ai_analysis(
        investigation_id,
        "offline_analysis",
        {
            "investigation_leads": [
                {
                    "target": "support.example.com",
                    "type": "domain",
                    "reason": "Subdomain discovered during passive scan",
                    "priority": "high",
                    "modules": ["dns_intel", "subdomain_enum"],
                }
            ],
            "entities_found": [
                {"type": "email", "value": "contact@example.com"},
                {"type": "domain", "value": "blog.example.net"},
            ],
        },
    )

    return investigation_id


def test_autopivot_suggest_offline_engine_returns_pivots(client):
    headers = _auth_headers()

    investigation_id = asyncio.run(
        _seed_investigation(client.app.state.investigation_manager, "test-user")
    )

    response = client.post(
        "/api/autopivot/suggest",
        json={"investigation_id": investigation_id, "max_pivots": 5},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert any(
        pivot["target"] == "support.example.com" for pivot in body["pivot_suggestions"]
    )
    assert all("reason" in pivot for pivot in body["pivot_suggestions"])


def test_autonomous_investigation_offline_engine(client):
    headers = _auth_headers()

    response = client.post(
        "/api/autopivot/autonomous",
        json={
            "target": "investigate-me.com",
            "target_type": "domain",
            "max_depth": 2,
            "max_pivots_per_level": 2,
        },
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    tree = body["investigation_tree"]
    assert body["total_targets"] >= 1
    assert body["total_pivots"] >= 1
    assert tree["levels"], "Expected at least one investigation level"
    assert tree["levels"][0][0]["pivots"], "Root level should include pivot suggestions"
