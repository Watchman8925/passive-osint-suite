from core.investigation_tracker import InvestigationTracker
from reporting.reporting_engine import EnhancedReportingEngine


def test_reporting_engine_uses_tracker_data(tmp_path):
    tracker = InvestigationTracker(storage_path=str(tmp_path / "tracker"))
    investigation_id = "inv-report"
    tracker.create_investigation(investigation_id, "Reporting Test")
    tracker.add_finding(
        investigation_id,
        finding_type="domain",
        value="example.com",
        source_module="seed",
        confidence=0.9,
        metadata={"notes": "seed"},
    )
    tracker.add_finding(
        investigation_id,
        finding_type="ip",
        value="198.51.100.5",
        source_module="dns",
        confidence=0.8,
        metadata={"dns_type": "A"},
    )
    tracker.upsert_lead(
        investigation_id,
        target="blog.example.com",
        target_type="domain",
        reason="Subdomain observed in certificate transparency logs",
        priority="high",
        suggested_modules=["domain_recon"],
    )

    engine = EnhancedReportingEngine(tracker=tracker)
    dataset = engine.build_dataset(investigation_id)
    assert dataset["investigation_id"] == investigation_id
    assert dataset["findings"], "Expected findings in dataset"

    summary = engine.generate_executive_summary(dataset)
    assert summary["key_findings"], "Summary should include key findings"
    risk = summary["risk_assessment"]
    assert "score" in risk and risk["score"] >= 0
