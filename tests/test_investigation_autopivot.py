import asyncio
import os
import sys
from types import SimpleNamespace

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("OSINT_SECRET_KEY", "test-secret-key")

import pytest

from api.api_server import AutopivotRequest, suggest_autopivots, app
from core.ai_engine import OSINTAIEngine
from core import investigation_tracker as tracker_module
from execution.engine import ExecutionEngine
from graph.adapter import GraphAdapter
from investigations.investigation_adapter import PersistentInvestigationStore
from evidence.store import EvidenceStore


@pytest.fixture
def tracker(tmp_path):
    tracker_module.set_tracker_instance(tracker_module.InvestigationTracker(
        storage_path=str(tmp_path / "tracker")
    ))
    try:
        yield tracker_module._tracker_instance
    finally:
        tracker_module.clear_tracker_instance()


async def _prepare_investigation(tmp_path, tracker):
    store = PersistentInvestigationStore(storage_dir=str(tmp_path / "store"))
    owner_id = "tester"
    inv_id = await store.create_investigation(
        name="Example Investigation",
        description="Testing persistence",
        targets=["example.com"],
        investigation_type="domain",
        priority="medium",
        tags=[],
        owner_id=owner_id,
        scheduled_start=None,
        auto_reporting=False,
    )
    await store.start_investigation(inv_id, owner_id)

    plan = SimpleNamespace(
        investigation_id=inv_id,
        tasks={
            "task-1": SimpleNamespace(
                id="task-1",
                capability_id="whois_lookup",
                inputs={"domain": "example.com"},
                depends_on=[],
                status="planned",
            )
        },
    )
    store._persist_plan(inv_id, plan)

    graph = GraphAdapter()
    evidence = EvidenceStore(base_dir=str(tmp_path / "evidence"))
    engine = ExecutionEngine(store=store, graph=graph, evidence=evidence)

    result = await engine.run_next_task(inv_id)
    assert result is not None and result.success

    return store, graph, owner_id, inv_id


def test_execution_persists_findings_and_results(tmp_path, tracker):
    async def _run():
        store, graph, owner_id, inv_id = await _prepare_investigation(tmp_path, tracker)

        findings = tracker.get_all_findings(inv_id)
        assert any(f.value == "example.com" for f in findings)

        record = await store.get_investigation(inv_id, owner_id)
        assert record is not None
        outputs = record["module_outputs"].get("whois_lookup")
        assert outputs, "whois_lookup results should be recorded"
        latest = outputs[-1]
        assert latest["entities"][0]["value"] == "example.com"
        assert latest["findings"], "Tracker finding references should be stored"
        assert record.get("pending_pivot_rescore") is True

    asyncio.run(_run())


def test_autopivot_endpoint_returns_evidence_based_pivots(tmp_path, tracker):
    async def _run():
        store, graph, owner_id, inv_id = await _prepare_investigation(tmp_path, tracker)

        engine = OSINTAIEngine(api_key=None, enable_autopivot=True, initialize_clients=False)
        engine.set_graph_adapter(graph)

        previous_store = getattr(app.state, "investigation_manager", None)
        previous_engine = getattr(app.state, "ai_engine", None)
        app.state.investigation_manager = store
        app.state.ai_engine = engine

        try:
            response = await suggest_autopivots(
                AutopivotRequest(investigation_id=inv_id, max_pivots=5),
                user_id=owner_id,
            )
        finally:
            app.state.investigation_manager = previous_store
            app.state.ai_engine = previous_engine

        pivots = response["pivot_suggestions"]
        assert pivots, "Autopivot endpoint should return suggestions"
        targets = {pivot["target"] for pivot in pivots}
        assert targets == {"example.com"}
        assert any("whois_lookup" in pivot["reason"] for pivot in pivots)

        updated = await store.get_investigation(inv_id, owner_id)
        assert updated is not None
        assert updated.get("pending_pivot_rescore") is False
        pivot_scores = updated.get("pivot_scores", {})
        assert "example.com" in pivot_scores.keys()
        assert pivot_scores["example.com"]["score"] == pivots[0]["confidence"]

    asyncio.run(_run())
