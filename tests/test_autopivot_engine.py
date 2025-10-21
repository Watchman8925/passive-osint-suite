import asyncio
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from unittest import mock

from core.local_llm_engine import LocalLLMEngine


def test_suggest_autopivots_generates_recommendations_without_model():
    engine = LocalLLMEngine(config={"force_backend": "rule_based"})

    tracker = engine.autonomous_engine.tracker
    tracker.create_investigation("inv-1", "Example Investigation")
    tracker.add_finding(
        "inv-1", "domain", "example.com", "seed", 0.9, metadata={"source": "seed"}
    )
    tracker.add_finding(
        "inv-1",
        "subdomain",
        "blog.example.com",
        "crt_sh",
        0.85,
        metadata={"source": "crt.sh"},
    )
    tracker.add_finding(
        "inv-1",
        "ip",
        "198.51.100.4",
        "dns_google",
        0.8,
        metadata={"dns_type": "A"},
    )

    investigation = {
        "id": "inv-1",
        "name": "Example Investigation",
        "targets": ["example.com"],
    }

    pivots = asyncio.run(engine.suggest_autopivots(investigation, max_pivots=5))

    assert pivots, "Expected at least one pivot suggestion"
    for pivot in pivots:
        assert pivot["target"], "pivot target should be populated"
        assert 0.0 < pivot["confidence"] <= 1.0
        assert pivot["priority"] in {"critical", "high", "medium", "low"}


def test_autonomous_investigation_produces_tree():
    engine = LocalLLMEngine(config={"force_backend": "rule_based"})

    async def fake_collect(investigation_id, target, target_type):
        engine.autonomous_engine.tracker.add_finding(
            investigation_id,
            "domain" if target_type == "domain" else target_type,
            target,
            "test_module",
            0.75,
        )
        return {
            "target": target,
            "target_type": target_type,
            "steps": [
                {
                    "module": "test_module",
                    "status": "success",
                    "summary": "stubbed",
                    "finding_ids": [],
                    "evidence_id": None,
                    "started_at": "2024-01-01T00:00:00",
                    "completed_at": "2024-01-01T00:00:01",
                }
            ],
        }

    with mock.patch.object(
        engine.autonomous_engine.collector, "collect", side_effect=fake_collect
    ):
        result = asyncio.run(
            engine.execute_autonomous_investigation(
                initial_target="example.com",
                target_type="domain",
                max_depth=1,
                max_pivots_per_level=1,
            )
        )

    assert result["total_targets"] >= 1
    assert result["total_pivots"] >= 0
    assert result["levels"], "Investigation levels should not be empty"
