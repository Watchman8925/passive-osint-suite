"""Tests for the CLI entry point lazy-loading behaviour."""

from __future__ import annotations

import logging
from typing import Dict, Any

import pytest

from main import OSINTSuite


def test_cli_suite_loads_modules_on_demand() -> None:
    """Modules are instantiated only when first accessed."""

    created = []

    class DomainRecon:
        def __init__(self) -> None:
            created.append("domain")

    class EmailIntel:
        def __init__(self) -> None:
            created.append("email")
            self.domain_recon = None

    registry: Dict[str, Dict[str, Any]] = {
        "domain_recon": {"class": DomainRecon, "category": "network"},
        "email_intel": {"class": EmailIntel, "category": "people"},
    }

    suite = OSINTSuite(module_registry_loader=lambda: registry)

    assert created == []

    available = suite.list_available_modules()
    assert available == ["domain_recon", "email_intel"]
    assert created == ["domain", "email"]

    email_module = suite.get_module("email_intel")
    domain_module = suite.get_module("domain_recon")
    assert email_module is not None
    assert domain_module is not None
    assert email_module.domain_recon is domain_module


def test_cli_suite_logs_module_failures(caplog: pytest.LogCaptureFixture) -> None:
    """A module that fails during construction is logged and skipped."""

    class BrokenModule:
        def __init__(self) -> None:
            raise RuntimeError("boom")

    registry = {"broken": {"class": BrokenModule, "category": "test"}}

    suite = OSINTSuite(module_registry_loader=lambda: registry)

    with caplog.at_level(logging.WARNING):
        assert suite.list_available_modules() == []

    assert "Failed to load module" in caplog.text
    assert suite.get_module("broken") is None
