"""Tests for the EvidenceStore default directory behaviour."""

import importlib
from pathlib import Path

import evidence.store as evidence_store_module


def test_evidence_store_uses_home_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("PASSIVE_OSINT_EVIDENCE_DIR", raising=False)
    original_home = Path.home
    monkeypatch.setattr(
        Path,
        "home",
        classmethod(lambda cls: tmp_path / "home"),  # type: ignore[arg-type]
    )
    importlib.reload(evidence_store_module)

    store = evidence_store_module.EvidenceStore()
    expected_path = tmp_path / "home" / ".passive_osint" / "evidence"
    assert store.base_dir == str(expected_path)
    assert expected_path.exists()

    monkeypatch.setattr(Path, "home", original_home)
    importlib.reload(evidence_store_module)
