import json
from pathlib import Path

import pytest

from investigations.investigation_adapter import PersistentInvestigationStore


@pytest.mark.asyncio
async def test_investigation_store_encrypts_records_on_disk(tmp_path):
    store = PersistentInvestigationStore(storage_dir=str(tmp_path))
    inv_id = await store.create_investigation(
        name="Sample",
        description="",
        targets=["example.com"],
        investigation_type="domain",
        priority="medium",
        tags=["demo"],
        owner_id="owner",
        scheduled_start=None,
        auto_reporting=False,
    )

    data_path = Path(tmp_path) / "investigations.json"
    payload = data_path.read_bytes()

    assert payload, "Encrypted payload should not be empty"

    with pytest.raises(json.JSONDecodeError):
        json.loads(payload.decode("utf-8"))

    reopened = PersistentInvestigationStore(storage_dir=str(tmp_path))
    record = await reopened.get_investigation(inv_id, owner_id="owner")
    assert record is not None
    assert record["id"] == inv_id


@pytest.mark.asyncio
async def test_investigation_store_uses_background_thread_when_aiofiles_missing(
    monkeypatch, tmp_path
):
    import investigations.investigation_adapter as adapter

    monkeypatch.setattr(adapter, "AIOFILES_AVAILABLE", False)

    calls = []
    original_to_thread = adapter.asyncio.to_thread

    async def tracking_to_thread(func, *args, **kwargs):
        calls.append(func)
        return await original_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(adapter.asyncio, "to_thread", tracking_to_thread)

    store = adapter.PersistentInvestigationStore(storage_dir=str(tmp_path))
    await store.create_investigation(
        name="ThreadTest",
        description=None,
        targets=["foo"],
        investigation_type="domain",
        priority="low",
        tags=[],
        owner_id="owner",
        scheduled_start=None,
        auto_reporting=True,
    )

    assert calls, "Expected to_thread to be used when aiofiles is unavailable"
