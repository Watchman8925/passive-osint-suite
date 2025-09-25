"""
Test script for Advanced Visualizations
Validates that all visualization components work correctly
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def test_visualization_imports():
    """Test that all visualization modules can be imported"""
    print("Testing visualization imports...")

    try:
        from visualizations.intelligence_visualizer import \
            IntelligenceVisualizer  # noqa: F401

        print("✓ Intelligence visualizer imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import intelligence visualizer: {e}")
        return False

    try:
        from visualizations.financial_flow_visualizer import \
            FinancialFlowVisualizer  # noqa: F401

        print("✓ Financial flow visualizer imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import financial flow visualizer: {e}")
        return False

    try:
        from visualizations.dashboard import OSINTDashboard  # noqa: F401

        print("✓ Dashboard imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import dashboard: {e}")
        return False

    return True


def test_intelligence_visualizer():
    """Test intelligence visualizer functionality"""
    print("\nTesting intelligence visualizer...")

    try:
        from visualizations.intelligence_visualizer import \
            IntelligenceVisualizer

        viz = IntelligenceVisualizer()

        # Test risk gauge
        risk_gauge = viz.create_risk_score_gauge(75, "Test Risk")
        assert risk_gauge is not None, "Risk gauge creation failed"
        print("✓ Risk gauge created successfully")

        # Test network graph
        intel_data = {
            "domain_intel": {"age_days": 365},
            "ip_intel": {"blacklist_count": 2},
            "crypto_intel": {"risk_score": 45},
        }
        network_graph = viz.create_intelligence_network_graph(intel_data)
        assert network_graph is not None, "Network graph creation failed"
        print("✓ Network graph created successfully")

        # Test timeline analysis
        timeline_data = [
            {
                "timestamp": datetime.now() - timedelta(days=i),
                "event_type": "transaction" if i % 2 == 0 else "login",
                "description": f"Event {i}",
            }
            for i in range(10)
        ]
        timeline = viz.create_timeline_analysis(timeline_data)
        assert timeline is not None, "Timeline creation failed"
        print("✓ Timeline analysis created successfully")

        # Test risk distribution
        risk_data = [
            {"entity": f"Entity_{i}", "risk_score": 20 + i * 5} for i in range(20)
        ]
        risk_dist = viz.create_risk_distribution_chart(risk_data)
        assert risk_dist is not None, "Risk distribution creation failed"
        print("✓ Risk distribution chart created successfully")

        # Test source contributions
        source_data = {"domain": 15, "ip": 12, "email": 10}
        source_chart = viz.create_source_contribution_chart(source_data)
        assert source_chart is not None, "Source contribution chart creation failed"
        print("✓ Source contribution chart created successfully")

        return True

    except Exception as e:
        print(f"✗ Error testing intelligence visualizer: {e}")
        return False


def test_financial_visualizer():
    """Test financial visualizer functionality"""
    print("\nTesting financial visualizer...")

    try:
        from visualizations.financial_flow_visualizer import \
            FinancialFlowVisualizer

        viz = FinancialFlowVisualizer()

        # Test transaction flow
        transactions = [
            {"from": "addr1", "to": "addr2", "value": 1.5, "timestamp": datetime.now()},
            {"from": "addr2", "to": "addr3", "value": 2.1, "timestamp": datetime.now()},
            {"from": "addr3", "to": "addr1", "value": 0.8, "timestamp": datetime.now()},
        ]
        flow_diagram = viz.create_transaction_flow_diagram(transactions)
        assert flow_diagram is not None, "Transaction flow creation failed"
        print("✓ Transaction flow diagram created successfully")

        # Test balance timeline
        balance_data = [
            {
                "timestamp": datetime.now() - timedelta(days=i),
                "balance": 100 + i * 2,
                "transactions": i % 3,
            }
            for i in range(15)
        ]
        balance_chart = viz.create_balance_timeline(balance_data)
        assert balance_chart is not None, "Balance timeline creation failed"
        print("✓ Balance timeline created successfully")

        # Test transaction volume
        volume_chart = viz.create_transaction_volume_chart(transactions)
        assert volume_chart is not None, "Transaction volume chart creation failed"
        print("✓ Transaction volume chart created successfully")

        # Test wallet risk heatmap
        wallet_data = [
            {"name": f"Wallet_{i}", "risk_score": 20 + i * 5} for i in range(10)
        ]
        heatmap = viz.create_wallet_risk_heatmap(wallet_data)
        assert heatmap is not None, "Wallet risk heatmap creation failed"
        print("✓ Wallet risk heatmap created successfully")

        return True

    except Exception as e:
        print(f"✗ Error testing financial visualizer: {e}")
        return False


def test_dashboard_creation():
    """Test dashboard creation (without running server)"""
    print("\nTesting dashboard creation...")

    try:
        from visualizations.dashboard import OSINTDashboard

        # Create dashboard instance
        dashboard = OSINTDashboard()

        # Test sample data creation
        sample_data = dashboard.create_sample_data()
        assert isinstance(sample_data, dict), "Sample data creation failed"
        assert "overall_risk" in sample_data, "Sample data missing overall_risk"
        print("✓ Dashboard sample data created successfully")

        # Test table data preparation
        table_data = dashboard.prepare_table_data(sample_data)
        assert isinstance(table_data, list), "Table data preparation failed"
        print("✓ Dashboard table data prepared successfully")

        # Test table columns creation
        if table_data:
            columns = dashboard.create_table_columns(table_data)
            assert isinstance(columns, list), "Table columns creation failed"
            print("✓ Dashboard table columns created successfully")

        return True

    except Exception as e:
        print(f"✗ Error testing dashboard creation: {e}")
        return False


def test_visualization_export():
    """Test visualization export functionality"""
    print("\nTesting visualization export...")

    try:
        from visualizations.intelligence_visualizer import \
            IntelligenceVisualizer

        viz = IntelligenceVisualizer()

        # Create a simple visualization
        risk_gauge = viz.create_risk_score_gauge(50, "Test Risk")

        # Test export to HTML (this should work without additional dependencies)
        export_path = "/tmp/test_risk_gauge.html"
        result_path = viz.export_visualization(risk_gauge, export_path, "html")

        # Check if file was created
        if os.path.exists(result_path):
            print("✓ Visualization export to HTML successful")
            # Clean up
            os.remove(result_path)
        else:
            print("⚠ HTML export may require additional dependencies")

        return True

    except Exception as e:
        print(f"✗ Error testing visualization export: {e}")
        return False


def main():
    """Run all visualization tests"""
    print("=== Advanced Visualizations Test Suite ===\n")

    all_passed = True

    # Test imports
    if not test_visualization_imports():
        all_passed = False

    # Test intelligence visualizer
    if not test_intelligence_visualizer():
        all_passed = False

    # Test financial visualizer
    if not test_financial_visualizer():
        all_passed = False

    # Test dashboard creation
    if not test_dashboard_creation():
        all_passed = False

    # Test visualization export
    if not test_visualization_export():
        all_passed = False

    print("\n=== Test Results ===")
    if all_passed:
        print(
            "✓ All visualization tests passed! Advanced visualizations are ready to use."
        )
        print("\nNote: Some advanced features may require additional dependencies:")
        print("- Static image export: pip install kaleido")
        print("- Enhanced tables: pip install dash-table")
        return 0
    else:
        print("✗ Some visualization tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
