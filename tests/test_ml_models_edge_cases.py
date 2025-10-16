"""
Test edge cases in ML models to validate bug fixes
Tests specifically for:
- crypto_pattern_detector.py unique_parties initialization bug
- flight_anomaly_detector.py duration uninitialized variable bug
"""

import os
import sys

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml_models.crypto_pattern_detector import CryptoPatternDetector
from ml_models.flight_anomaly_detector import FlightAnomalyDetector


class TestCryptoPatternDetectorEdgeCases:
    """Test edge cases in CryptoPatternDetector"""

    def test_extract_features_with_transactions(self):
        """Test that extract_features handles transactions correctly.
        This should trigger the unique_parties bug if not fixed."""
        detector = CryptoPatternDetector()

        # Create address data with transactions
        address_data = {
            "balance": 100.0,
            "transaction_count": 5,
            "first_seen": "2023-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
            "transactions": [
                {"from": "0xabc123", "to": "0xdef456", "value": 10.0},
                {"from": "0xdef456", "to": "0xghi789", "value": 20.0},
                {"from": "0xghi789", "to": "0xabc123", "value": 15.0},
            ],
        }

        # This should not raise an AttributeError
        features = detector.extract_features(address_data)

        # Verify features were extracted
        assert len(features) == len(detector.feature_columns)
        assert isinstance(features[4], (int, float))  # unique_counterparties feature

    def test_extract_features_with_empty_transactions(self):
        """Test that extract_features handles empty transactions list"""
        detector = CryptoPatternDetector()

        address_data = {
            "balance": 50.0,
            "transaction_count": 0,
            "transactions": [],
        }

        # Should not raise any errors
        features = detector.extract_features(address_data)
        assert len(features) == len(detector.feature_columns)

    def test_extract_features_with_malformed_transactions(self):
        """Test that extract_features handles malformed transactions"""
        detector = CryptoPatternDetector()

        address_data = {
            "balance": 50.0,
            "transaction_count": 3,
            "transactions": [
                {"from": "0xabc123"},  # Missing 'to'
                {"to": "0xdef456"},  # Missing 'from'
                None,  # Invalid transaction
                "not a dict",  # Invalid transaction
            ],
        }

        # Should handle errors gracefully
        features = detector.extract_features(address_data)
        assert len(features) == len(detector.feature_columns)


class TestFlightAnomalyDetectorEdgeCases:
    """Test edge cases in FlightAnomalyDetector"""

    def test_extract_features_with_missing_times(self):
        """Test that extract_features handles missing times correctly.
        This should trigger the duration bug if not fixed."""
        detector = FlightAnomalyDetector()

        # Flight data with missing times
        flight_data = {
            "departure": {"code": "JFK", "lat": 40.6413, "lon": -73.7781},
            "arrival": {"code": "LAX", "lat": 33.9425, "lon": -118.4081},
            # Missing departure_time and arrival_time
            "aircraft": {"type": "B737"},
            "passenger_count": 150,
        }

        # This should not raise an UnboundLocalError
        features = detector.extract_features(flight_data)

        # Verify features were extracted
        assert len(features) == len(detector.feature_columns)
        assert isinstance(features[1], (int, float))  # duration feature

    def test_extract_features_with_invalid_times(self):
        """Test that extract_features handles invalid time formats"""
        detector = FlightAnomalyDetector()

        flight_data = {
            "departure": {"code": "JFK", "lat": 40.6413, "lon": -73.7781},
            "arrival": {"code": "LAX", "lat": 33.9425, "lon": -118.4081},
            "departure_time": "invalid-date-format",
            "arrival_time": "also-invalid",
            "aircraft": {"type": "B737"},
            "passenger_count": 150,
        }

        # Should handle invalid dates gracefully
        features = detector.extract_features(flight_data)
        assert len(features) == len(detector.feature_columns)
        # Duration should be 0 for invalid times
        assert features[1] == 0

    def test_extract_features_with_valid_times(self):
        """Test that extract_features correctly calculates duration with valid times"""
        detector = FlightAnomalyDetector()

        flight_data = {
            "departure": {"code": "JFK", "lat": 40.6413, "lon": -73.7781},
            "arrival": {"code": "LAX", "lat": 33.9425, "lon": -118.4081},
            "departure_time": "2024-01-15T10:00:00Z",
            "arrival_time": "2024-01-15T15:00:00Z",  # 5 hours flight
            "aircraft": {"type": "B737"},
            "passenger_count": 150,
        }

        features = detector.extract_features(flight_data)
        assert len(features) == len(detector.feature_columns)
        # Duration should be approximately 5 hours
        assert 4.5 <= features[1] <= 5.5

    def test_extract_features_with_partial_times(self):
        """Test behavior when only one time is provided"""
        detector = FlightAnomalyDetector()

        # Only departure time
        flight_data = {
            "departure": {"code": "JFK", "lat": 40.6413, "lon": -73.7781},
            "arrival": {"code": "LAX", "lat": 33.9425, "lon": -118.4081},
            "departure_time": "2024-01-15T10:00:00Z",
            # Missing arrival_time
            "aircraft": {"type": "B737"},
            "passenger_count": 150,
        }

        features = detector.extract_features(flight_data)
        assert len(features) == len(detector.feature_columns)
        # Duration should be 0 when arrival time is missing
        assert features[1] == 0
