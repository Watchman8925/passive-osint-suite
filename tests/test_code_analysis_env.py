"""Regression tests for the CodeAnalysisEngine environment helpers."""

import os

from modules.code_analysis import CodeAnalysisEngine


def test_tool_env_preserves_existing_path(monkeypatch):
    original_path = "/usr/local/bin"
    monkeypatch.setenv("PATH", original_path)
    engine = CodeAnalysisEngine()

    env = engine._get_tool_env()

    assert env["PATH"].endswith(original_path)
    expected_paths = [
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~/bin"),
        os.path.join(os.getcwd(), "theHarvester", "bin"),
    ]
    for expected in expected_paths:
        assert expected in env["PATH"]
