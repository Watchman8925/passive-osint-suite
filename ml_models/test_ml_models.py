"""
Test script for ML Models
Validates that all models can be imported and basic functionality works
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def test_imports():
    """Test that all ML model modules can be imported"""
    print("Testing ML model imports...")

    try:
        from ml_models.crypto_pattern_detector import \
            CryptoPatternDetector  # noqa: F401
        from ml_models.crypto_pattern_detector import \
            analyze_crypto_address  # noqa: F401

        print("✓ Cryptocurrency pattern detector imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import crypto pattern detector: {e}")
        return False

    try:
        from ml_models.flight_anomaly_detector import \
            FlightAnomalyDetector  # noqa: F401
        from ml_models.flight_anomaly_detector import \
            analyze_flight_anomaly  # noqa: F401

        print("✓ Flight anomaly detector imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import flight anomaly detector: {e}")
        return False

    try:
        from ml_models.risk_scoring_engine import (  # noqa: F401
            RiskScoringEngine, calculate_comprehensive_risk)

        print("✓ Risk scoring engine imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import risk scoring engine: {e}")
        return False

    try:
        from ml_models import MLModelsManager, ml_manager  # noqa: F401

        print("✓ ML models manager imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import ML models manager: {e}")
        return False

    return True


def test_basic_functionality():
    """Test basic functionality of ML models"""
    print("\nTesting basic ML model functionality...")

    try:
        from ml_models import ml_manager

        # Test crypto analysis with sample data
        crypto_data = {
            "balance": 50.0,
            "transaction_count": 25,
            "avg_transaction_value": 2.0,
            "unique_counterparties": 10,
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
            "exchanges": ["Binance"],
            "transactions": [],
        }

        result = ml_manager.analyze_crypto_address(crypto_data)
        print(f"✓ Crypto analysis result: risk_score={result.get('risk_score', 'N/A')}")

        # Test flight analysis with sample data
        flight_data = {
            "departure": {"code": "JFK", "lat": 40.6413, "lon": -73.7781},
            "arrival": {"code": "LAX", "lat": 33.9425, "lon": -118.4081},
            "departure_time": "2024-01-15T10:30:00Z",
            "arrival_time": "2024-01-15T13:45:00Z",
            "aircraft": {"type": "B737"},
            "passenger_count": 150,
            "weather": {"visibility": 10, "wind_speed": 15},
        }

        result = ml_manager.analyze_flight_anomaly(flight_data)
        print(
            f"✓ Flight analysis result: anomaly_score={result.get('anomaly_score', 'N/A')}"
        )

        # Test comprehensive risk calculation
        intelligence_data = {
            "crypto_intel": {"risk_score": 45},
            "flight_intel": {"anomaly_score": 35},
            "domain_intel": {"age_days": 365, "ssl_valid": True},
            "ip_intel": {"blacklist_count": 0},
            "threat_intel": {"ioc_match_count": 0},
        }

        result = ml_manager.calculate_comprehensive_risk(intelligence_data)
        print(
            f"✓ Comprehensive risk result: risk_score={result.get('risk_score', 'N/A')}"
        )

        return True

    except Exception as e:
        print(f"✗ Error testing basic functionality: {e}")
        return False


def test_model_manager():
    """Test the ML models manager functionality"""
    print("\nTesting ML models manager...")

    try:
        from ml_models import ml_manager

        # Test model status
        status = ml_manager.get_model_status()
        print(f"✓ Model status: {status}")

        # Test metadata export
        metadata = ml_manager.export_model_metadata()
        print(f"✓ Metadata exported with {len(metadata)} keys")

        # Test health report
        health = ml_manager.get_model_health_report()
        print(f"✓ Health report: {health['overall_health']}")

        return True

    except Exception as e:
        print(f"✗ Error testing model manager: {e}")
        return False


def main():
    """Run all tests"""
    print("=== ML Models Test Suite ===\n")

    all_passed = True

    # Test imports
    if not test_imports():
        all_passed = False

    # Test basic functionality
    if not test_basic_functionality():
        all_passed = False

    # Test model manager
    if not test_model_manager():
        all_passed = False

    print("\n=== Test Results ===")
    if all_passed:
        print("✓ All tests passed! ML models are ready to use.")
        return 0
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
