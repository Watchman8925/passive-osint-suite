"""Unit tests for investigation task dispatch across core module types."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("OSINT_SECRET_KEY", "test-secret-key")

from datetime import datetime
from typing import Any, Dict

import pytest

from investigations.investigation_manager import (
    Investigation,
    InvestigationManager,
    InvestigationStatus,
    InvestigationTask,
    Priority,
    TaskStatus,
)
from modules import MODULE_REGISTRY


class _DummyAuditTrail:
    def log_action(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - noop
        return None


class _DummyResultEncryption:  # pragma: no cover - noop container for dependency
    pass


class _DummySecretsManager:  # pragma: no cover - noop container for dependency
    def get_secret(self, _key: str) -> None:
        return None


class _DummySuite:  # pragma: no cover - noop container for dependency
    pass


@pytest.fixture()
def manager(tmp_path) -> InvestigationManager:
    """Provide an investigation manager with isolated filesystem paths."""

    return InvestigationManager(
        osint_suite=_DummySuite(),
        audit_trail=_DummyAuditTrail(),
        result_encryption=_DummyResultEncryption(),
        secrets_manager=_DummySecretsManager(),
        storage_path=str(tmp_path / "investigations"),
    )


def _build_investigation(task: InvestigationTask) -> Investigation:
    """Construct a minimal investigation wrapping a single task."""

    now = datetime.now()
    return Investigation(
        id=task.parent_id,
        name="Test Investigation",
        description="Unit test harness",
        investigation_type="unit-test",
        status=InvestigationStatus.ACTIVE,
        priority=Priority.MEDIUM,
        targets=task.targets,
        tags=[],
        analyst="Tester",
        organization="Test Org",
        created_at=now,
        started_at=now,
        completed_at=None,
        deadline=None,
        estimated_duration=0,
        tasks={task.id: task},
        dependencies={},
        results={},
        ai_analysis=None,
        configuration={},
        metadata={},
    )


def _build_task(
    *,
    investigation_id: str,
    task_type: str,
    targets: list[str],
    parameters: Dict[str, Any],
) -> InvestigationTask:
    now = datetime.now()
    return InvestigationTask(
        id=f"task-{task_type}",
        parent_id=investigation_id,
        name=f"{task_type} task",
        task_type=task_type,
        targets=targets,
        parameters=parameters,
        status=TaskStatus.PENDING,
        priority=Priority.MEDIUM,
        dependencies=[],
        estimated_duration=0,
        actual_duration=None,
        created_at=now,
        started_at=None,
        completed_at=None,
        result=None,
        error=None,
        retry_count=0,
        max_retries=1,
        progress=0.0,
        metadata={},
    )


_TASK_CASES = [
    (
        "domain_recon",
        "domain_recon",
        "analyze_domain",
        True,
        ["example.com"],
        {},
    ),
    (
        "ip_intelligence",
        "ip_intel",
        "analyze_ip",
        True,
        ["8.8.8.8"],
        {},
    ),
    (
        "email_intelligence",
        "email_intel",
        "analyze_email",
        True,
        ["test@example.com"],
        {},
    ),
    (
        "company_intelligence",
        "company_intel",
        "analyze_company",
        False,
        ["Example Corp"],
        {"domain": "example.com"},
    ),
    (
        "flight_intelligence",
        "flight_intel",
        "analyze_aircraft",
        False,
        ["N12345"],
        {"identifier_type": "registration"},
    ),
    (
        "crypto_intelligence",
        "crypto_intel",
        "analyze_crypto_address",
        False,
        ["1BitcoinEaterAddressDontSendf59kuE"],
        {"currency_type": "bitcoin"},
    ),
    (
        "passive_search",
        "passive_search",
        "analyze_target",
        False,
        ["example.com"],
        {"target_type": "domain"},
    ),
]


@pytest.mark.parametrize(
    "task_type,module_key,method_name,returns_status,targets,parameters",
    _TASK_CASES,
)
def test_execute_task_persists_results(
    manager: InvestigationManager,
    monkeypatch: pytest.MonkeyPatch,
    task_type: str,
    module_key: str,
    method_name: str,
    returns_status: bool,
    targets: list[str],
    parameters: Dict[str, Any],
) -> None:
    async def _run() -> None:
        module_info = MODULE_REGISTRY[module_key]
        module_class = module_info["class"]

        call_counter: Dict[str, int] = {"count": 0}

        def _stub_method(self, target: str, **kwargs: Any) -> Dict[str, Any]:
            call_counter["count"] += 1
            payload = {"target": target, "kwargs": kwargs}
            if returns_status:
                return {"status": "success", "data": payload}
            return payload

        monkeypatch.setattr(module_class, method_name, _stub_method)

        investigation_id = "investigation-1"
        task = _build_task(
            investigation_id=investigation_id,
            task_type=task_type,
            targets=targets,
            parameters=parameters,
        )
        investigation = _build_investigation(task)

        manager.investigations[investigation_id] = investigation

        async def _noop_save(self, _investigation: Investigation) -> None:
            return None

        monkeypatch.setattr(InvestigationManager, "_save_investigation", _noop_save)

        await manager._execute_task(investigation_id, task.id)

        assert call_counter["count"] == len(targets)

        stored_result = investigation.results[task.id]
        assert stored_result["status"] == "completed"

        for target in targets:
            normalized = stored_result["data"][target]
            assert "status" in normalized
            assert normalized["status"] in {"success", "error"}

        task_after = investigation.tasks[task.id]
        assert task_after.status == TaskStatus.COMPLETED
        assert task_after.result == stored_result

    asyncio.run(_run())
