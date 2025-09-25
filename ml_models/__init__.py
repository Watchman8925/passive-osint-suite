"""
ML Models Manager
Coordinates all machine learning models and provides unified interface
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .crypto_pattern_detector import CryptoPatternDetector
from .flight_anomaly_detector import FlightAnomalyDetector
from .risk_scoring_engine import RiskScoringEngine


class MLModelsManager:
    """Manager for all machine learning models in the OSINT suite"""

    def __init__(self, models_dir: str = "ml_models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)

        self.logger = logging.getLogger(__name__)

        # Initialize all models
        self.crypto_detector = CryptoPatternDetector(
            model_path=str(self.models_dir / "crypto_pattern_detector.pkl")
        )

        self.flight_detector = FlightAnomalyDetector(
            model_path=str(self.models_dir / "flight_anomaly_detector.pkl")
        )

        self.risk_engine = RiskScoringEngine(
            model_path=str(self.models_dir / "risk_scoring_engine.pkl")
        )

        # Model status tracking
        self.model_status = {
            "crypto_detector": False,
            "flight_detector": False,
            "risk_engine": False,
        }

        # Training data cache
        self.training_cache = {"crypto": [], "flight": [], "risk": []}

    def load_all_models(self) -> Dict[str, bool]:
        """Load all trained models from disk"""
        self.logger.info("Loading all ML models...")

        results = {}

        # Load crypto detector
        try:
            results["crypto_detector"] = self.crypto_detector.load_model()
            self.model_status["crypto_detector"] = results["crypto_detector"]
        except Exception as e:
            self.logger.error(f"Error loading crypto detector: {e}")
            results["crypto_detector"] = False

        # Load flight detector
        try:
            results["flight_detector"] = self.flight_detector.load_model()
            self.model_status["flight_detector"] = results["flight_detector"]
        except Exception as e:
            self.logger.error(f"Error loading flight detector: {e}")
            results["flight_detector"] = False

        # Load risk engine
        try:
            results["risk_engine"] = self.risk_engine.load_model()
            self.model_status["risk_engine"] = results["risk_engine"]
        except Exception as e:
            self.logger.error(f"Error loading risk engine: {e}")
            results["risk_engine"] = False

        loaded_count = sum(results.values())
        self.logger.info(f"Loaded {loaded_count}/{len(results)} models successfully")

        return results

    def save_all_models(self) -> Dict[str, bool]:
        """Save all trained models to disk"""
        self.logger.info("Saving all ML models...")

        results = {}

        # Save crypto detector
        try:
            self.crypto_detector.save_model()
            results["crypto_detector"] = True
        except Exception as e:
            self.logger.error(f"Error saving crypto detector: {e}")
            results["crypto_detector"] = False

        # Save flight detector
        try:
            self.flight_detector.save_model()
            results["flight_detector"] = True
        except Exception as e:
            self.logger.error(f"Error saving flight detector: {e}")
            results["flight_detector"] = False

        # Save risk engine
        try:
            self.risk_engine.save_model()
            results["risk_engine"] = True
        except Exception as e:
            self.logger.error(f"Error saving risk engine: {e}")
            results["risk_engine"] = False

        saved_count = sum(results.values())
        self.logger.info(f"Saved {saved_count}/{len(results)} models successfully")

        return results

    def train_crypto_detector(
        self, training_data: List[Dict], labels: Optional[List[int]] = None
    ) -> bool:
        """Train the cryptocurrency pattern detector"""
        try:
            self.logger.info("Training cryptocurrency pattern detector...")
            self.crypto_detector.train_model(training_data, labels)
            self.model_status["crypto_detector"] = True
            self.logger.info("Cryptocurrency pattern detector training completed")
            return True
        except Exception as e:
            self.logger.error(f"Error training crypto detector: {e}")
            return False

    def train_flight_detector(
        self, training_data: List[Dict], labels: Optional[List[int]] = None
    ) -> bool:
        """Train the flight anomaly detector"""
        try:
            self.logger.info("Training flight anomaly detector...")
            self.flight_detector.train_model(training_data, labels)
            self.model_status["flight_detector"] = True
            self.logger.info("Flight anomaly detector training completed")
            return True
        except Exception as e:
            self.logger.error(f"Error training flight detector: {e}")
            return False

    def train_risk_engine(
        self, training_data: List[Dict], labels: Optional[List[int]] = None
    ) -> bool:
        """Train the risk scoring engine"""
        try:
            self.logger.info("Training risk scoring engine...")
            self.risk_engine.train_model(training_data, labels)
            self.model_status["risk_engine"] = True
            self.logger.info("Risk scoring engine training completed")
            return True
        except Exception as e:
            self.logger.error(f"Error training risk engine: {e}")
            return False

    def analyze_crypto_address(self, address_data: Dict) -> Dict:
        """Analyze cryptocurrency address for risk patterns"""
        return self.crypto_detector.predict_risk(address_data)

    def analyze_flight_anomaly(self, flight_data: Dict) -> Dict:
        """Analyze flight data for anomalies"""
        return self.flight_detector.predict_anomaly(flight_data)

    def calculate_comprehensive_risk(self, intelligence_data: Dict) -> Dict:
        """Calculate comprehensive risk score from all intelligence sources"""
        return self.risk_engine.calculate_risk_score(intelligence_data)

    def get_model_status(self) -> Dict[str, bool]:
        """Get the training status of all models"""
        return self.model_status.copy()

    def get_model_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for all trained models"""
        metrics = {}

        # Crypto detector metrics
        if self.model_status["crypto_detector"]:
            try:
                feature_importance = self.crypto_detector.get_feature_importance()
                metrics["crypto_detector"] = {
                    "feature_importance": feature_importance,
                    "status": "trained",
                }
            except Exception as e:
                metrics["crypto_detector"] = {"error": str(e)}

        # Flight detector metrics
        if self.model_status["flight_detector"]:
            try:
                feature_importance = self.flight_detector.get_feature_importance()
                metrics["flight_detector"] = {
                    "feature_importance": feature_importance,
                    "status": "trained",
                }
            except Exception as e:
                metrics["flight_detector"] = {"error": str(e)}

        # Risk engine doesn't have feature importance in the same way
        metrics["risk_engine"] = {
            "status": "trained" if self.model_status["risk_engine"] else "not_trained"
        }

        return metrics

    def update_training_data(
        self, model_type: str, new_data: List[Dict], labels: Optional[List[int]] = None
    ):
        """Update training data cache for a specific model"""
        if model_type not in self.training_cache:
            self.logger.error(f"Unknown model type: {model_type}")
            return

        self.training_cache[model_type].extend(new_data)

        # Keep only recent data (last 10,000 samples)
        if len(self.training_cache[model_type]) > 10000:
            self.training_cache[model_type] = self.training_cache[model_type][-10000:]

        self.logger.info(
            f"Updated {model_type} training data cache: {len(self.training_cache[model_type])} samples"
        )

    def retrain_models(self, force: bool = False) -> Dict[str, bool]:
        """Retrain all models using cached training data"""
        results = {}

        # Retrain crypto detector
        if force or not self.model_status["crypto_detector"]:
            if self.training_cache["crypto"]:
                results["crypto_detector"] = self.train_crypto_detector(
                    self.training_cache["crypto"]
                )

        # Retrain flight detector
        if force or not self.model_status["flight_detector"]:
            if self.training_cache["flight"]:
                results["flight_detector"] = self.train_flight_detector(
                    self.training_cache["flight"]
                )

        # Retrain risk engine
        if force or not self.model_status["risk_engine"]:
            if self.training_cache["risk"]:
                results["risk_engine"] = self.train_risk_engine(
                    self.training_cache["risk"]
                )

        return results

    def export_model_metadata(self) -> Dict[str, Any]:
        """Export metadata about all models"""
        metadata = {
            "export_timestamp": datetime.now().isoformat(),
            "models_dir": str(self.models_dir),
            "model_status": self.model_status,
            "training_data_sizes": {
                model: len(data) for model, data in self.training_cache.items()
            },
        }

        # Add model-specific metadata
        if self.model_status["crypto_detector"]:
            metadata["crypto_detector"] = {
                "feature_columns": self.crypto_detector.feature_columns,
                "is_trained": self.crypto_detector.is_trained,
            }

        if self.model_status["flight_detector"]:
            metadata["flight_detector"] = {
                "feature_columns": self.flight_detector.feature_columns,
                "is_trained": self.flight_detector.is_trained,
            }

        if self.model_status["risk_engine"]:
            metadata["risk_engine"] = {
                "source_weights": self.risk_engine.source_weights,
                "risk_categories": self.risk_engine.risk_categories,
                "is_trained": self.risk_engine.is_trained,
            }

        return metadata

    def save_metadata(self, filepath: Optional[str] = None) -> bool:
        """Save model metadata to file"""
        if filepath is None:
            filepath = self.models_dir / "models_metadata.json"

        try:
            metadata = self.export_model_metadata()
            with open(filepath, "w") as f:
                json.dump(metadata, f, indent=2, default=str)

            self.logger.info(f"Model metadata saved to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving metadata: {e}")
            return False

    def load_metadata(self, filepath: Optional[str] = None) -> bool:
        """Load model metadata from file"""
        if filepath is None:
            filepath = self.models_dir / "models_metadata.json"

        try:
            if not os.path.exists(filepath):
                self.logger.warning(f"Metadata file not found: {filepath}")
                return False

            with open(filepath, "r") as f:
                metadata = json.load(f)

            # Update status from metadata
            if "model_status" in metadata:
                self.model_status.update(metadata["model_status"])

            self.logger.info(f"Model metadata loaded from {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading metadata: {e}")
            return False

    def get_model_health_report(self) -> Dict[str, Any]:
        """Generate a comprehensive health report for all models"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_health": "healthy",
            "models": {},
            "recommendations": [],
        }

        # Check each model
        for model_name, is_trained in self.model_status.items():
            model_info = {
                "status": "trained" if is_trained else "not_trained",
                "training_data_available": len(
                    self.training_cache.get(
                        model_name.replace("_detector", "").replace("_engine", ""), []
                    )
                )
                > 0,
            }

            # Check if model files exist
            model_file = getattr(self, model_name).model_path
            model_info["model_file_exists"] = os.path.exists(model_file)

            report["models"][model_name] = model_info

            # Generate recommendations
            if not is_trained:
                report["recommendations"].append(f"Train {model_name} model")
                report["overall_health"] = "needs_training"

            if not model_info["model_file_exists"] and is_trained:
                report["recommendations"].append(f"Save {model_name} model to disk")
                report["overall_health"] = "needs_saving"

        return report


# Global instance
ml_manager = MLModelsManager()


# Convenience functions
def analyze_crypto_risk(address_data: Dict) -> Dict:
    """Convenience function for crypto risk analysis"""
    return ml_manager.analyze_crypto_address(address_data)


def analyze_flight_risk(flight_data: Dict) -> Dict:
    """Convenience function for flight risk analysis"""
    return ml_manager.analyze_flight_anomaly(flight_data)


def calculate_overall_risk(intelligence_data: Dict) -> Dict:
    """Convenience function for comprehensive risk calculation"""
    return ml_manager.calculate_comprehensive_risk(intelligence_data)
