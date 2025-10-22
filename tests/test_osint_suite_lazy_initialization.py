"""Tests for the primary OSINT suite lazy initialization behaviour."""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any, Dict

import pytest

import osint_suite


class _AsyncAllServices:
    async def validate_all_services(self) -> Dict[str, Any]:
        return {}


@pytest.mark.asyncio
async def test_passive_modules_initialize_on_demand(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Passive modules are not instantiated until explicitly requested."""

    created: list[str] = []

    class PassiveModule:
        def __init__(self) -> None:
            created.append("passive")

    fake_module = ModuleType("fake.passive")
    fake_module.PassiveModule = PassiveModule  # type: ignore[attr-defined]

    original_import = osint_suite.import_module

    def import_stub(name: str, package: str | None = None) -> ModuleType:
        if name == "fake.passive":
            return fake_module
        return original_import(name, package)

    monkeypatch.setattr(osint_suite, "import_module", import_stub)
    monkeypatch.setattr(osint_suite.secrets_manager, "get_secret", lambda _: "")
    monkeypatch.setattr(osint_suite, "get_tor_status", lambda: {"active": False})

    suite = osint_suite.OSINTSuite(
        passive_module_specs={"fake": ("fake.passive", "PassiveModule")}
    )
    suite.api_manager = _AsyncAllServices()

    assert created == []

    result = await suite.validate_system()
    assert created == ["passive"]
    assert result["passive_modules"]["fake"] is True


def _install_stub_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install lightweight stand-ins for optional components."""

    reporting_engine_module = ModuleType("reporting.reporting_engine")

    class DummyEngine:
        def __init__(self, ai_engine: Any | None = None) -> None:
            self.ai_engine = ai_engine

        def generate_executive_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
            return {"summary": "executive", "data": data}

        def generate_technical_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
            return {"summary": "technical", "data": data}

        def generate_threat_assessment(self, data: Dict[str, Any]) -> Dict[str, Any]:
            return {"summary": "threat", "data": data}

        def generate_custom_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
            return {"summary": "custom", "data": data}

    reporting_engine_module.EnhancedReportingEngine = DummyEngine  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules, "reporting.reporting_engine", reporting_engine_module
    )

    scheduler_module = ModuleType("reporting.report_scheduler")

    class DummyScheduler:
        def __init__(self, _engine: Any) -> None:
            self.engine = _engine

    scheduler_module.ReportScheduler = DummyScheduler  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "reporting.report_scheduler", scheduler_module)

    realtime_module = ModuleType("realtime.realtime_feeds")

    class DummyRealtime:
        def __init__(self) -> None:
            self.started = False

    realtime_module.RealTimeIntelligenceFeed = DummyRealtime  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "realtime.realtime_feeds", realtime_module)


@pytest.mark.asyncio
async def test_component_initialization_lazily_loads_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core components only import heavy dependencies when required."""

    _install_stub_modules(monkeypatch)

    created: list[str] = []

    class PassiveModule:
        def __init__(self) -> None:
            created.append("passive")

    fake_module = ModuleType("fake.passive")
    fake_module.PassiveModule = PassiveModule  # type: ignore[attr-defined]

    monkeypatch.setattr(osint_suite, "get_tor_status", lambda: {"active": True})
    monkeypatch.setattr(osint_suite.secrets_manager, "get_secret", lambda _: "")
    monkeypatch.setattr(
        osint_suite, "import_module", lambda name, package=None: fake_module
    )

    suite = osint_suite.OSINTSuite(
        passive_module_specs={"fake": ("fake.passive", "PassiveModule")}
    )
    suite.api_manager = _AsyncAllServices()

    assert suite.reporting_engine is None

    intelligence = {
        "sources": {"fake": {"finding": True}},
        "target": "example.com",
        "recommendations": ["do something"],
    }

    report = await suite.generate_custom_report(intelligence)
    assert report["metadata"]["report_type"] == "executive_summary"
    assert suite.reporting_engine is not None
    assert created == []  # report generation should not load passive modules

    await suite.perform_passive_intelligence_gathering("example.com")
    assert created == ["passive"]
