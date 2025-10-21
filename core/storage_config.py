"""Shared storage configuration for the passive OSINT suite.

All persistent components (investigation tracker, chat history, evidence
artifacts, scheduler metadata, etc.) should resolve their on-disk location via
this module so we maintain a single expansion-friendly data root.

The base directory defaults to ``./platform_data`` but can be overridden via
the ``OSINT_DATA_PATH`` environment variable. The module eagerly creates the
directory to avoid race conditions when multiple subsystems bootstrap at the
same time.
"""

from __future__ import annotations

import os
from pathlib import Path


def _ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


_DATA_ROOT = _ensure_directory(
    Path(os.getenv("OSINT_DATA_PATH", "./platform_data")).expanduser().resolve()
)


def data_root() -> Path:
    """Return the root directory for all persistent platform data."""

    return _DATA_ROOT


def resolve_path(*segments: str) -> Path:
    """Resolve a child path relative to :func:`data_root` and ensure parents."""

    path = _DATA_ROOT.joinpath(*segments)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


__all__ = ["data_root", "resolve_path"]

