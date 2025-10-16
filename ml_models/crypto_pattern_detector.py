"""
Cryptocurrency Pattern Recognition and Risk Analysis ML Model
Uses machine learning to detect suspicious patterns in crypto transactions
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


class CryptoPatternDetector:
    """Machine learning model for cryptocurrency pattern detection"""

    def __init__(self, model_path: str = "ml_models/crypto_pattern_detector.pkl"):
        self.model_path = model_path
        self.logger = logging.getLogger(__name__)

        # Initialize models
        self.classifier = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
        )

        self.anomaly_detector = IsolationForest(
            contamination=0.1, random_state=42, n_jobs=-1
        )

        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

        # Feature columns
        self.feature_columns = [
            "balance",
            "transaction_count",
            "avg_transaction_value",
            "transaction_frequency",
            "unique_counterparties",
            "time_since_first_tx",
            "time_since_last_tx",
            "balance_volatility",
            "transaction_velocity",
            "exchange_connections",
            "mixer_usage",
        ]

        self.is_trained = False

    def extract_features(self, address_data: Dict) -> np.ndarray:
        """Extract features from cryptocurrency address data"""
        features = []

        # Basic transaction features
        balance = float(address_data.get("balance", 0))
        tx_count = int(address_data.get("transaction_count", 0))

        features.append(balance)
        features.append(tx_count)

        # Average transaction value
        avg_tx_value = balance / max(tx_count, 1)
        features.append(avg_tx_value)

        # Transaction frequency (transactions per day)
        first_seen = address_data.get("first_seen")
        last_seen = address_data.get("last_seen")

        if first_seen and last_seen:
            try:
                first_date = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                last_date = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                days_active = max((last_date - first_date).days, 1)
                frequency = tx_count / days_active
                features.append(frequency)
            except (ValueError, ZeroDivisionError, AttributeError):
                features.append(0)
        else:
            features.append(0)

        # Unique counterparties
        transactions = address_data.get("transactions", [])
        unique_parties = set()
        for tx in transactions:
            if isinstance(tx, dict):
                if "from" in tx:
                    unique_parties.add(tx["from"])
                if "to" in tx:
                    unique_parties.add(tx["to"])
        features.append(len(unique_parties))

        # Time features
        now = datetime.now()
        if first_seen:
            try:
                first_date = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                # Remove timezone info to avoid comparison issues
                if first_date.tzinfo is not None:
                    first_date = first_date.replace(tzinfo=None)
                time_since_first = (now - first_date).days
                features.append(time_since_first)
            except (ValueError, AttributeError, TypeError):
                features.append(0)
        else:
            features.append(0)

        if last_seen:
            try:
                last_date = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                # Remove timezone info to avoid comparison issues
                if last_date.tzinfo is not None:
                    last_date = last_date.replace(tzinfo=None)
                time_since_last = (now - last_date).days
                features.append(time_since_last)
            except (ValueError, AttributeError, TypeError):
                features.append(0)
        else:
            features.append(0)

        # Balance volatility (simplified)
        if transactions:
            values = [
                float(tx.get("value", 0)) for tx in transactions if isinstance(tx, dict)
            ]
            if values:
                volatility = np.std(values) / max(np.mean(values), 1)
                features.append(volatility)
            else:
                features.append(0)
        else:
            features.append(0)

        # Transaction velocity (recent activity)
        recent_txs = 0
        week_ago = now - timedelta(days=7)
        for tx in transactions:
            if isinstance(tx, dict) and "timestamp" in tx:
                try:
                    tx_date = datetime.fromisoformat(
                        tx["timestamp"].replace("Z", "+00:00")
                    )
                    if tx_date > week_ago:
                        recent_txs += 1
                except (ValueError, KeyError, AttributeError):
                    pass
        features.append(recent_txs)

        # Exchange connections
        exchanges = address_data.get("exchanges", [])
        features.append(len(exchanges) if exchanges else 0)

        # Mixer usage (simplified heuristic)
        mixer_indicators = ["mixer", "tornado", "privacy", "anonymizer"]
        mixer_usage = 0
        for tx in transactions:
            if isinstance(tx, dict):
                tx_str = json.dumps(tx).lower()
                if any(indicator in tx_str for indicator in mixer_indicators):
                    mixer_usage += 1
        features.append(mixer_usage)

        return np.array(features)

    def train_model(self, training_data: List[Dict], labels: List[int] = None):
        """Train the cryptocurrency pattern detection model"""
        self.logger.info("Training cryptocurrency pattern detection model...")

        # Extract features from training data
        X = []
        for data in training_data:
            features = self.extract_features(data)
            X.append(features)

        X = np.array(X)

        # If no labels provided, use unsupervised learning
        if labels is None or len(labels) == 0:
            self.logger.info("No labels provided, training anomaly detector...")
            self.anomaly_detector.fit(X)
            self.is_trained = True
            return

        # Supervised learning with labels
        y = np.array(labels)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train classifier
        self.classifier.fit(X_train_scaled, y_train)

        # Evaluate model
        y_pred = self.classifier.predict(X_test_scaled)
        y_prob = self.classifier.predict_proba(X_test_scaled)[:, 1]

        self.logger.info("Model Training Results:")
        self.logger.info(classification_report(y_test, y_pred))
        self.logger.info(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.3f}")

        self.is_trained = True

    def predict_risk(self, address_data: Dict) -> Dict:
        """Predict risk score for a cryptocurrency address"""
        if not self.is_trained:
            return {"risk_score": 50, "confidence": 0, "patterns": []}

        try:
            features = self.extract_features(address_data)
            features_scaled = self.scaler.transform([features])

            # Get prediction probabilities
            risk_prob = self.classifier.predict_proba(features_scaled)[0][1]
            risk_score = int(risk_prob * 100)

            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function([features])[0]
            is_anomaly = self.anomaly_detector.predict([features])[0] == -1

            # Identify suspicious patterns
            patterns = self._identify_patterns(features, address_data)

            return {
                "risk_score": risk_score,
                "confidence": float(risk_prob),
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": float(anomaly_score),
                "patterns": patterns,
                "recommendations": self._generate_recommendations(risk_score, patterns),
            }

        except Exception as e:
            self.logger.error(f"Error predicting risk: {e}")
            return {"risk_score": 50, "confidence": 0, "patterns": [], "error": str(e)}

    def _identify_patterns(self, features: np.ndarray, address_data: Dict) -> List[str]:
        """Identify suspicious patterns in the address data"""
        patterns = []

        # High balance pattern
        if features[0] > 100:  # balance > 100 BTC/ETH
            patterns.append("high_balance")

        # High transaction frequency
        if features[3] > 10:  # > 10 transactions per day
            patterns.append("high_frequency")

        # Many unique counterparties
        if features[4] > 50:  # > 50 unique addresses
            patterns.append("many_counterparties")

        # Recent activity spike
        if features[8] > 20:  # > 20 transactions in last week
            patterns.append("activity_spike")

        # Exchange connections
        if features[9] > 3:  # Connected to multiple exchanges
            patterns.append("multi_exchange")

        # Privacy tool usage
        if features[10] > 0:  # Used privacy tools
            patterns.append("privacy_tools")

        # Old inactive address suddenly active
        if features[5] > 365 and features[8] > 5:  # Old address with recent activity
            patterns.append("sudden_activity")

        return patterns

    def _generate_recommendations(
        self, risk_score: int, patterns: List[str]
    ) -> List[str]:
        """Generate investigation recommendations based on risk score and patterns"""
        recommendations = []

        if risk_score > 80:
            recommendations.append("HIGH PRIORITY: Immediate investigation required")
        elif risk_score > 60:
            recommendations.append("MEDIUM PRIORITY: Enhanced monitoring recommended")

        if "high_balance" in patterns:
            recommendations.append("Monitor for large value transfers")

        if "activity_spike" in patterns:
            recommendations.append("Investigate source of recent activity increase")

        if "multi_exchange" in patterns:
            recommendations.append("Check exchange compliance and KYC status")

        if "privacy_tools" in patterns:
            recommendations.append(
                "Enhanced due diligence for privacy-focused transactions"
            )

        if "sudden_activity" in patterns:
            recommendations.append(
                "Verify address ownership and transaction legitimacy"
            )

        return recommendations

    def save_model(self):
        """Save the trained model to disk"""
        try:
            model_data = {
                "classifier": self.classifier,
                "anomaly_detector": self.anomaly_detector,
                "scaler": self.scaler,
                "feature_columns": self.feature_columns,
                "is_trained": self.is_trained,
                "trained_at": datetime.now().isoformat(),
            }

            joblib.dump(model_data, self.model_path)
            self.logger.info(f"Model saved to {self.model_path}")

        except Exception as e:
            self.logger.error(f"Error saving model: {e}")

    def load_model(self):
        """Load a trained model from disk"""
        try:
            if not os.path.exists(self.model_path):
                self.logger.warning(f"Model file not found: {self.model_path}")
                return False

            model_data = joblib.load(self.model_path)

            self.classifier = model_data["classifier"]
            self.anomaly_detector = model_data["anomaly_detector"]
            self.scaler = model_data["scaler"]
            self.feature_columns = model_data["feature_columns"]
            self.is_trained = model_data["is_trained"]

            self.logger.info(f"Model loaded from {self.model_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores from the trained model"""
        if not self.is_trained or not hasattr(self.classifier, "feature_importances_"):
            return {}

        importance_scores = self.classifier.feature_importances_
        return dict(zip(self.feature_columns, importance_scores))


# Global instance
crypto_detector = CryptoPatternDetector()


def analyze_crypto_address(address_data: Dict) -> Dict:
    """Convenience function for crypto address analysis"""
    return crypto_detector.predict_risk(address_data)
