"""
Flight Anomaly Detection ML Model
Detects suspicious flight patterns and potential security threats
"""

import logging
import os
from datetime import datetime
from typing import Dict, List

import joblib
import numpy as np
from geopy.distance import geodesic
from sklearn.cluster import DBSCAN
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


class FlightAnomalyDetector:
    """Machine learning model for flight anomaly detection"""

    def __init__(self, model_path: str = "ml_models/flight_anomaly_detector.pkl"):
        self.model_path = model_path
        self.logger = logging.getLogger(__name__)

        # Initialize models
        self.classifier = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
        )

        self.cluster_detector = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

        # Feature columns
        self.feature_columns = [
            "flight_distance",
            "flight_duration",
            "altitude_change",
            "speed_variation",
            "route_deviation",
            "time_of_day",
            "day_of_week",
            "season",
            "aircraft_type_risk",
            "departure_delay",
            "arrival_delay",
            "weather_conditions",
            "passenger_count",
            "cargo_weight",
            "fuel_efficiency",
        ]

        self.is_trained = False

        # Known high-risk airports and routes
        self.high_risk_airports = {
            "high_risk": ["SVO", "DME", "LED", "IST", "DOH", "AUH", "DXB"],
            "sanctions_related": ["TEI", "ADA", "ERC", "VAN", "BJV"],
            "remote_locations": ["SVX", "KJA", "UUS", "GDX", "PKC"],
        }

    def extract_features(self, flight_data: Dict) -> np.ndarray:
        """Extract features from flight data"""
        features = []

        # Basic flight metrics
        departure = flight_data.get("departure", {})
        arrival = flight_data.get("arrival", {})

        # Calculate flight distance
        dep_coords = (departure.get("lat", 0), departure.get("lon", 0))
        arr_coords = (arrival.get("lat", 0), arrival.get("lon", 0))
        distance = geodesic(dep_coords, arr_coords).kilometers
        features.append(distance)

        # Flight duration
        duration = 0
        dep_time = flight_data.get("departure_time")
        arr_time = flight_data.get("arrival_time")
        if dep_time and arr_time:
            try:
                dep_dt = datetime.fromisoformat(dep_time.replace("Z", "+00:00"))
                arr_dt = datetime.fromisoformat(arr_time.replace("Z", "+00:00"))
                duration = (arr_dt - dep_dt).total_seconds() / 3600  # hours
                features.append(duration)
            except (ValueError, AttributeError):
                features.append(0)
        else:
            features.append(0)

        # Altitude change (simplified)
        dep_alt = departure.get("altitude", 0)
        arr_alt = arrival.get("altitude", 0)
        alt_change = abs(arr_alt - dep_alt)
        features.append(alt_change)

        # Speed variation (based on distance and duration)
        if duration > 0:
            avg_speed = distance / duration  # km/h
            # Normal commercial flight speed is ~800-900 km/h
            speed_deviation = abs(avg_speed - 850) / 850
            features.append(speed_deviation)
        else:
            features.append(0)

        # Route deviation (simplified - would need actual flight path)
        features.append(0)  # Placeholder for route deviation

        # Time-based features
        if dep_time:
            try:
                dep_dt = datetime.fromisoformat(dep_time.replace("Z", "+00:00"))
                time_of_day = dep_dt.hour + dep_dt.minute / 60
                features.append(time_of_day)

                day_of_week = dep_dt.weekday()
                features.append(day_of_week)

                # Season (0=winter, 1=spring, 2=summer, 3=fall)
                month = dep_dt.month
                if month in [12, 1, 2]:
                    season = 0
                elif month in [3, 4, 5]:
                    season = 1
                elif month in [6, 7, 8]:
                    season = 2
                else:
                    season = 3
                features.append(season)
            except (ValueError, AttributeError):
                features.extend([12, 0, 0])  # Default to noon, Monday, winter
        else:
            features.extend([12, 0, 0])

        # Aircraft type risk score
        aircraft = flight_data.get("aircraft", {})
        aircraft_type = aircraft.get("type", "").upper()
        risk_score = self._calculate_aircraft_risk(aircraft_type)
        features.append(risk_score)

        # Delay features
        dep_delay = flight_data.get("departure_delay", 0)
        arr_delay = flight_data.get("arrival_delay", 0)
        features.append(dep_delay)
        features.append(arr_delay)

        # Weather conditions (simplified)
        weather = flight_data.get("weather", {})
        weather_score = self._calculate_weather_risk(weather)
        features.append(weather_score)

        # Passenger and cargo info
        passenger_count = flight_data.get("passenger_count", 100)
        cargo_weight = flight_data.get("cargo_weight", 0)
        features.append(passenger_count)
        features.append(cargo_weight)

        # Fuel efficiency (simplified)
        if distance > 0 and duration > 0:
            fuel_efficiency = distance / (duration * 100)  # km per 100 hours
            features.append(fuel_efficiency)
        else:
            features.append(0)

        return np.array(features)

    def _calculate_aircraft_risk(self, aircraft_type: str) -> float:
        """Calculate risk score based on aircraft type"""
        high_risk_types = ["IL76", "AN12", "TU204", "IL96"]
        medium_risk_types = ["B737", "A320", "B777", "A330"]

        if any(risk_type in aircraft_type for risk_type in high_risk_types):
            return 0.8
        elif any(risk_type in aircraft_type for risk_type in medium_risk_types):
            return 0.4
        else:
            return 0.1

    def _calculate_weather_risk(self, weather: Dict) -> float:
        """Calculate risk score based on weather conditions"""
        risk_score = 0

        if weather.get("visibility", 10) < 5:
            risk_score += 0.3
        if weather.get("wind_speed", 0) > 30:
            risk_score += 0.3
        if weather.get("precipitation", 0) > 5:
            risk_score += 0.2
        if weather.get("icing", False):
            risk_score += 0.4

        return min(risk_score, 1.0)

    def _check_route_risk(self, departure_code: str, arrival_code: str) -> float:
        """Check if route involves high-risk airports"""
        risk_score = 0

        dep_risk = any(
            departure_code in airports for airports in self.high_risk_airports.values()
        )
        arr_risk = any(
            arrival_code in airports for airports in self.high_risk_airports.values()
        )

        if dep_risk or arr_risk:
            risk_score += 0.5

        # Additional risk for certain route combinations
        high_risk_routes = [("SVO", "DAM"), ("IST", "TEI"), ("DOH", "ADA")]

        route = (departure_code, arrival_code)
        if route in high_risk_routes:
            risk_score += 0.5

        return min(risk_score, 1.0)

    def train_model(self, training_data: List[Dict], labels: List[int] = None):
        """Train the flight anomaly detection model"""
        self.logger.info("Training flight anomaly detection model...")

        # Extract features from training data
        X = []
        for data in training_data:
            features = self.extract_features(data)
            X.append(features)

        X = np.array(X)

        if labels is None or len(labels) == 0:
            # Unsupervised clustering for anomaly detection
            self.logger.info(
                "No labels provided, using clustering for anomaly detection..."
            )
            self.cluster_detector.fit(X)
            self.is_trained = True
            return

        # Supervised learning
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

        self.logger.info("Flight Anomaly Model Training Results:")
        self.logger.info(classification_report(y_test, y_pred))
        self.logger.info(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.3f}")

        self.is_trained = True

    def predict_anomaly(self, flight_data: Dict) -> Dict:
        """Predict anomaly score for a flight"""
        if not self.is_trained:
            return {"anomaly_score": 50, "confidence": 0, "risk_factors": []}

        try:
            features = self.extract_features(flight_data)
            features_scaled = self.scaler.transform([features])

            # Get prediction
            anomaly_prob = self.classifier.predict_proba(features_scaled)[0][1]
            anomaly_score = int(anomaly_prob * 100)

            # Clustering-based anomaly detection
            cluster_labels = self.cluster_detector.fit_predict([features])
            is_outlier = cluster_labels[0] == -1

            # Identify risk factors
            risk_factors = self._identify_risk_factors(features, flight_data)

            # Route-specific risk
            dep_code = flight_data.get("departure", {}).get("code", "")
            arr_code = flight_data.get("arrival", {}).get("code", "")
            route_risk = self._check_route_risk(dep_code, arr_code)

            final_score = min(anomaly_score + int(route_risk * 20), 100)

            return {
                "anomaly_score": final_score,
                "confidence": float(anomaly_prob),
                "is_outlier": bool(is_outlier),
                "route_risk": float(route_risk),
                "risk_factors": risk_factors,
                "recommendations": self._generate_recommendations(
                    final_score, risk_factors
                ),
            }

        except Exception as e:
            self.logger.error(f"Error predicting flight anomaly: {e}")
            return {
                "anomaly_score": 50,
                "confidence": 0,
                "risk_factors": [],
                "error": str(e),
            }

    def _identify_risk_factors(
        self, features: np.ndarray, flight_data: Dict
    ) -> List[str]:
        """Identify risk factors in flight data"""
        risk_factors = []

        # Unusual flight duration
        if (
            features[1] < 1 or features[1] > 20
        ):  # Less than 1 hour or more than 20 hours
            risk_factors.append("unusual_duration")

        # High speed variation
        if features[3] > 0.3:  # More than 30% deviation from normal speed
            risk_factors.append("speed_anomaly")

        # Night flight
        if 0 <= features[5] <= 6 or 22 <= features[5] <= 24:
            risk_factors.append("night_flight")

        # Weekend flight (potentially unusual)
        if features[6] >= 5:  # Saturday or Sunday
            risk_factors.append("weekend_flight")

        # High-risk aircraft
        if features[8] > 0.6:
            risk_factors.append("high_risk_aircraft")

        # Significant delays
        if features[9] > 120 or features[10] > 120:  # More than 2 hours delay
            risk_factors.append("major_delays")

        # Adverse weather
        if features[11] > 0.5:
            risk_factors.append("adverse_weather")

        # Unusual passenger count
        if features[12] < 10 or features[12] > 500:
            risk_factors.append("unusual_passenger_count")

        # Heavy cargo
        if features[13] > 50000:  # More than 50 tons
            risk_factors.append("heavy_cargo")

        return risk_factors

    def _generate_recommendations(
        self, anomaly_score: int, risk_factors: List[str]
    ) -> List[str]:
        """Generate investigation recommendations"""
        recommendations = []

        if anomaly_score > 80:
            recommendations.append("CRITICAL: Immediate security screening required")
        elif anomaly_score > 60:
            recommendations.append(
                "HIGH PRIORITY: Enhanced security measures recommended"
            )

        if "unusual_duration" in risk_factors:
            recommendations.append("Verify flight route and stops")

        if "speed_anomaly" in risk_factors:
            recommendations.append("Check flight data integrity and pilot reports")

        if "night_flight" in risk_factors:
            recommendations.append("Review operational necessity and crew fatigue")

        if "high_risk_aircraft" in risk_factors:
            recommendations.append("Verify aircraft maintenance and certification")

        if "major_delays" in risk_factors:
            recommendations.append("Investigate delay causes and passenger impact")

        if "adverse_weather" in risk_factors:
            recommendations.append("Monitor weather conditions and diversion plans")

        if "heavy_cargo" in risk_factors:
            recommendations.append("Verify cargo manifest and security screening")

        return recommendations

    def save_model(self):
        """Save the trained model to disk"""
        try:
            model_data = {
                "classifier": self.classifier,
                "cluster_detector": self.cluster_detector,
                "scaler": self.scaler,
                "feature_columns": self.feature_columns,
                "is_trained": self.is_trained,
                "trained_at": datetime.now().isoformat(),
            }

            joblib.dump(model_data, self.model_path)
            self.logger.info(f"Flight anomaly model saved to {self.model_path}")

        except Exception as e:
            self.logger.error(f"Error saving flight model: {e}")

    def load_model(self):
        """Load a trained model from disk"""
        try:
            if not os.path.exists(self.model_path):
                self.logger.warning(f"Model file not found: {self.model_path}")
                return False

            model_data = joblib.load(self.model_path)

            self.classifier = model_data["classifier"]
            self.cluster_detector = model_data["cluster_detector"]
            self.scaler = model_data["scaler"]
            self.feature_columns = model_data["feature_columns"]
            self.is_trained = model_data["is_trained"]

            self.logger.info(f"Flight anomaly model loaded from {self.model_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error loading flight model: {e}")
            return False

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        if not self.is_trained or not hasattr(self.classifier, "feature_importances_"):
            return {}

        importance_scores = self.classifier.feature_importances_
        return dict(zip(self.feature_columns, importance_scores))


# Global instance
flight_detector = FlightAnomalyDetector()


def analyze_flight_anomaly(flight_data: Dict) -> Dict:
    """Convenience function for flight anomaly analysis"""
    return flight_detector.predict_anomaly(flight_data)
