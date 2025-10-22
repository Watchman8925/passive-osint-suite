from __future__ import annotations

import threading

from modules.pattern_matching import PatternMatchingEngine


def test_lazy_tool_detection(monkeypatch):
    calls = []

    def fake_check(tool_name: str) -> bool:
        calls.append(tool_name)
        return True

    monkeypatch.setattr(PatternMatchingEngine, "_check_tool", staticmethod(fake_check))

    engine = PatternMatchingEngine()
    assert calls == []

    assert engine._tool_available("yara") is True
    assert calls == ["yara"]


def test_directory_scan_respects_cancellation(tmp_path, monkeypatch):
    engine = PatternMatchingEngine(max_files=10)
    monkeypatch.setattr(engine, "_tool_available", lambda name: True)

    scanned = []
    cancel_event = threading.Event()

    def fake_yara(file_path: str, rules_path=None):
        scanned.append(file_path)
        cancel_event.set()
        return {
            "success": True,
            "match_count": 1,
            "matches": ["hit"],
            "file_path": file_path,
        }

    monkeypatch.setattr(engine, "yara_scan_file", fake_yara)

    allowed_dir = tmp_path / "allowed"
    denied_dir = tmp_path / "denied"
    allowed_dir.mkdir()
    denied_dir.mkdir()

    allowed_file = allowed_dir / "match.bin"
    denied_file = denied_dir / "skip.bin"
    allowed_file.write_bytes(b"binary data")
    denied_file.write_bytes(b"binary data")

    result = engine.yara_scan_directory(
        str(tmp_path),
        allowed_roots=[str(allowed_dir)],
        denylist=[str(denied_dir)],
        cancel_event=cancel_event,
    )

    assert result["files_scanned"] == 1
    assert result.get("cancelled") is True
    assert result["total_matches"] == 1
    assert result["results"][0]["file_path"] == "allowed/match.bin"
    assert denied_file not in scanned


def test_directory_scan_truncates_on_limit(tmp_path, monkeypatch):
    engine = PatternMatchingEngine(max_files=1)
    monkeypatch.setattr(engine, "_tool_available", lambda name: True)
    monkeypatch.setattr(
        engine,
        "yara_scan_file",
        lambda file_path, rules_path=None: {"success": True, "match_count": 0},
    )

    for index in range(3):
        file_path = tmp_path / f"file_{index}.txt"
        file_path.write_text("data")

    result = engine.yara_scan_directory(str(tmp_path))
    assert result["files_scanned"] == 1
    assert result.get("truncated") is True
