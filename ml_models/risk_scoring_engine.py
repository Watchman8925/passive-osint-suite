"""
Risk Scoring Engine ML Model
Combines multiple intelligence sources to generate comprehensive risk scores
"""

import logging
import os
from datetime import datetime
from typing import Dict, List

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, VotingClassifier
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import LabelEncoder, StandardScaler


class RiskScoringEngine:
    """Advanced risk scoring engine combining multiple intelligence sources"""

    def __init__(self, model_path: str = "ml_models/risk_scoring_engine.pkl"):
        self.model_path = model_path
        self.logger = logging.getLogger(__name__)

        # Initialize ensemble models
        self.gb_classifier = GradientBoostingClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42
        )

        self.lr_classifier = LogisticRegression(random_state=42, max_iter=1000)

        self.nb_classifier = GaussianNB()

        # Ensemble classifier
        self.ensemble = VotingClassifier(
            estimators=[
                ("gradient_boosting", self.gb_classifier),
                ("logistic_regression", self.lr_classifier),
                ("naive_bayes", self.nb_classifier),
            ],
            voting="soft",
        )

        self.scaler = StandardScaler()
        self.feature_selector = SelectKBest(score_func=f_classif, k=20)
        self.label_encoder = LabelEncoder()

        # Intelligence source weights
        self.source_weights = {
            "domain_intel": 0.15,
            "ip_intel": 0.12,
            "email_intel": 0.10,
            "social_media": 0.08,
            "crypto_intel": 0.15,
            "company_intel": 0.12,
            "flight_intel": 0.10,
            "web_intel": 0.08,
            "threat_intel": 0.10,
        }

        # Risk categories and their base scores
        self.risk_categories = {
            "low": {"min_score": 0, "max_score": 30, "weight": 1.0},
            "medium": {"min_score": 31, "max_score": 60, "weight": 1.5},
            "high": {"min_score": 61, "max_score": 80, "weight": 2.0},
            "critical": {"min_score": 81, "max_score": 100, "weight": 3.0},
        }

        self.is_trained = False

    def extract_features(self, intelligence_data: Dict) -> np.ndarray:
        """Extract features from combined intelligence data"""
        features = []

        # Domain intelligence features
        domain_data = intelligence_data.get("domain_intel", {})
        features.extend(self._extract_domain_features(domain_data))

        # IP intelligence features
        ip_data = intelligence_data.get("ip_intel", {})
        features.extend(self._extract_ip_features(ip_data))

        # Email intelligence features
        email_data = intelligence_data.get("email_intel", {})
        features.extend(self._extract_email_features(email_data))

        # Social media features
        social_data = intelligence_data.get("social_media", {})
        features.extend(self._extract_social_features(social_data))

        # Cryptocurrency features
        crypto_data = intelligence_data.get("crypto_intel", {})
        features.extend(self._extract_crypto_features(crypto_data))

        # Company intelligence features
        company_data = intelligence_data.get("company_intel", {})
        features.extend(self._extract_company_features(company_data))

        # Flight intelligence features
        flight_data = intelligence_data.get("flight_intel", {})
        features.extend(self._extract_flight_features(flight_data))

        # Web intelligence features
        web_data = intelligence_data.get("web_intel", {})
        features.extend(self._extract_web_features(web_data))

        # Threat intelligence features
        threat_data = intelligence_data.get("threat_intel", {})
        features.extend(self._extract_threat_features(threat_data))

        # Temporal features
        temporal_data = intelligence_data.get("temporal", {})
        features.extend(self._extract_temporal_features(temporal_data))

        return np.array(features)

    def _extract_domain_features(self, domain_data: Dict) -> List[float]:
        """Extract domain-specific features"""
        features = []

        # Domain age (normalized)
        age_days = domain_data.get("age_days", 365)
        features.append(min(age_days / 3650, 1.0))  # Max 10 years

        # Registration privacy
        features.append(1.0 if domain_data.get("privacy_enabled", False) else 0.0)

        # SSL certificate validity
        ssl_valid = domain_data.get("ssl_valid", True)
        features.append(1.0 if ssl_valid else 0.0)

        # Subdomain count
        subdomain_count = len(domain_data.get("subdomains", []))
        features.append(min(subdomain_count / 50, 1.0))

        # DNS record count
        dns_count = domain_data.get("dns_record_count", 0)
        features.append(min(dns_count / 20, 1.0))

        return features

    def _extract_ip_features(self, ip_data: Dict) -> List[float]:
        """Extract IP-specific features"""
        features = []

        # Geolocation risk score
        geo_risk = ip_data.get("geolocation_risk", 0.5)
        features.append(geo_risk)

        # ASN reputation
        asn_reputation = ip_data.get("asn_reputation", 0.5)
        features.append(asn_reputation)

        # Blacklist count
        blacklist_count = ip_data.get("blacklist_count", 0)
        features.append(min(blacklist_count / 10, 1.0))

        # Port exposure
        open_ports = len(ip_data.get("open_ports", []))
        features.append(min(open_ports / 100, 1.0))

        # VPN/Tor detection
        is_vpn = ip_data.get("is_vpn", False)
        is_tor = ip_data.get("is_tor", False)
        features.append(1.0 if is_vpn or is_tor else 0.0)

        return features

    def _extract_email_features(self, email_data: Dict) -> List[float]:
        """Extract email-specific features"""
        features = []

        # Domain reputation
        domain_rep = email_data.get("domain_reputation", 0.5)
        features.append(domain_rep)

        # SPF/DKIM/DMARC compliance
        spf = email_data.get("spf_pass", False)
        dkim = email_data.get("dkim_pass", False)
        dmarc = email_data.get("dmarc_pass", False)
        compliance_score = (spf + dkim + dmarc) / 3.0
        features.append(compliance_score)

        # Bounce rate
        bounce_rate = email_data.get("bounce_rate", 0.0)
        features.append(bounce_rate)

        # Spam complaints
        spam_rate = email_data.get("spam_complaints", 0.0)
        features.append(spam_rate)

        # Age of email account
        age_days = email_data.get("account_age_days", 365)
        features.append(min(age_days / 3650, 1.0))

        return features

    def _extract_social_features(self, social_data: Dict) -> List[float]:
        """Extract social media features"""
        features = []

        # Account verification status
        verified = social_data.get("verified", False)
        features.append(1.0 if verified else 0.0)

        # Follower/following ratio
        followers = social_data.get("followers_count", 0)
        following = social_data.get("following_count", 1)
        ratio = followers / following if following > 0 else 0
        features.append(min(ratio / 10, 1.0))

        # Posting frequency
        posts_per_day = social_data.get("posts_per_day", 1)
        features.append(min(posts_per_day / 20, 1.0))

        # Engagement rate
        engagement_rate = social_data.get("engagement_rate", 0.0)
        features.append(engagement_rate)

        # Account age
        age_days = social_data.get("account_age_days", 365)
        features.append(min(age_days / 3650, 1.0))

        return features

    def _extract_crypto_features(self, crypto_data: Dict) -> List[float]:
        """Extract cryptocurrency features"""
        features = []

        # Wallet balance (normalized)
        balance = crypto_data.get("balance", 0)
        features.append(min(balance / 1000, 1.0))  # Max 1000 units

        # Transaction count
        tx_count = crypto_data.get("transaction_count", 0)
        features.append(min(tx_count / 1000, 1.0))

        # Risk score from crypto detector
        risk_score = crypto_data.get("risk_score", 50) / 100.0
        features.append(risk_score)

        # Exchange connections
        exchange_count = len(crypto_data.get("exchanges", []))
        features.append(min(exchange_count / 10, 1.0))

        # Privacy tool usage
        privacy_usage = crypto_data.get("privacy_tools_used", 0)
        features.append(min(privacy_usage / 5, 1.0))

        return features

    def _extract_company_features(self, company_data: Dict) -> List[float]:
        """Extract company intelligence features"""
        features = []

        # Company size (normalized)
        size = company_data.get("employee_count", 100)
        features.append(min(size / 10000, 1.0))  # Max 10k employees

        # Industry risk score
        industry_risk = company_data.get("industry_risk", 0.5)
        features.append(industry_risk)

        # Regulatory compliance score
        compliance = company_data.get("compliance_score", 0.5)
        features.append(compliance)

        # Financial health score
        financial_health = company_data.get("financial_health", 0.5)
        features.append(financial_health)

        # Geographic risk
        geo_risk = company_data.get("geographic_risk", 0.5)
        features.append(geo_risk)

        return features

    def _extract_flight_features(self, flight_data: Dict) -> List[float]:
        """Extract flight intelligence features"""
        features = []

        # Flight frequency
        flight_count = flight_data.get("flight_count", 0)
        features.append(min(flight_count / 100, 1.0))

        # Route risk score
        route_risk = flight_data.get("route_risk", 0.5)
        features.append(route_risk)

        # Anomaly score from flight detector
        anomaly_score = flight_data.get("anomaly_score", 50) / 100.0
        features.append(anomaly_score)

        # Aircraft type risk
        aircraft_risk = flight_data.get("aircraft_risk", 0.5)
        features.append(aircraft_risk)

        # Operational irregularities
        irregularities = flight_data.get("irregularities", 0)
        features.append(min(irregularities / 10, 1.0))

        return features

    def _extract_web_features(self, web_data: Dict) -> List[float]:
        """Extract web intelligence features"""
        features = []

        # Domain reputation
        domain_rep = web_data.get("domain_reputation", 0.5)
        features.append(domain_rep)

        # Content risk score
        content_risk = web_data.get("content_risk", 0.5)
        features.append(content_risk)

        # Malware detection
        malware_found = web_data.get("malware_detected", False)
        features.append(1.0 if malware_found else 0.0)

        # SSL/TLS security score
        ssl_score = web_data.get("ssl_security_score", 0.5)
        features.append(ssl_score)

        # Traffic analysis
        traffic_score = web_data.get("traffic_anomaly_score", 0.5)
        features.append(traffic_score)

        return features

    def _extract_threat_features(self, threat_data: Dict) -> List[float]:
        """Extract threat intelligence features"""
        features = []

        # Threat actor association
        actor_score = threat_data.get("actor_association_score", 0.5)
        features.append(actor_score)

        # Malware family detection
        malware_score = threat_data.get("malware_family_score", 0.5)
        features.append(malware_score)

        # C2 server communication
        c2_score = threat_data.get("c2_communication_score", 0.5)
        features.append(c2_score)

        # Attack pattern similarity
        pattern_score = threat_data.get("attack_pattern_score", 0.5)
        features.append(pattern_score)

        # IOC match count
        ioc_count = threat_data.get("ioc_match_count", 0)
        features.append(min(ioc_count / 20, 1.0))

        return features

    def _extract_temporal_features(self, temporal_data: Dict) -> List[float]:
        """Extract temporal features"""
        features = []

        # Activity recency
        last_activity_days = temporal_data.get("last_activity_days", 30)
        features.append(min(last_activity_days / 365, 1.0))

        # Activity frequency
        activity_frequency = temporal_data.get("activity_frequency", 1)
        features.append(min(activity_frequency / 100, 1.0))

        # Pattern consistency
        consistency_score = temporal_data.get("pattern_consistency", 0.5)
        features.append(consistency_score)

        # Seasonal variation
        seasonal_var = temporal_data.get("seasonal_variation", 0.5)
        features.append(seasonal_var)

        # Trend analysis
        trend_score = temporal_data.get("trend_score", 0.5)
        features.append(trend_score)

        return features

    def train_model(self, training_data: List[Dict], labels: List[int] = None):
        """Train the risk scoring ensemble model"""
        self.logger.info("Training risk scoring ensemble model...")

        # Extract features from training data
        X = []
        for data in training_data:
            features = self.extract_features(data)
            X.append(features)

        X = np.array(X)

        if labels is None or len(labels) == 0:
            self.logger.warning("No labels provided for supervised training")
            return

        y = np.array(labels)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Feature selection
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        X_test_selected = self.feature_selector.transform(X_test)

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train_selected)
        X_test_scaled = self.scaler.transform(X_test_selected)

        # Train ensemble
        self.ensemble.fit(X_train_scaled, y_train)

        # Evaluate model
        y_pred = self.ensemble.predict(X_test_scaled)
        y_prob = self.ensemble.predict_proba(X_test_scaled)[:, 1]

        self.logger.info("Risk Scoring Model Training Results:")
        self.logger.info(classification_report(y_test, y_pred))
        self.logger.info(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.3f}")

        # Cross-validation
        cv_scores = cross_val_score(self.ensemble, X_train_scaled, y_train, cv=5)
        self.logger.info(f"Cross-validation scores: {cv_scores}")
        self.logger.info(
            f"Mean CV score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})"
        )

        self.is_trained = True

    def calculate_risk_score(self, intelligence_data: Dict) -> Dict:
        """Calculate comprehensive risk score from intelligence data"""
        if not self.is_trained:
            return self._calculate_weighted_score(intelligence_data)

        try:
            features = self.extract_features(intelligence_data)
            features_selected = self.feature_selector.transform([features])
            features_scaled = self.scaler.transform(features_selected)

            # Get ensemble prediction
            risk_prob = self.ensemble.predict_proba(features_scaled)[0][1]
            ml_score = int(risk_prob * 100)

            # Get weighted score for comparison
            weighted_score = self._calculate_weighted_score(intelligence_data)

            # Combine ML and weighted scores
            final_score = int((ml_score * 0.7) + (weighted_score["risk_score"] * 0.3))

            # Determine risk category
            risk_category = self._determine_risk_category(final_score)

            # Generate risk factors
            risk_factors = self._identify_risk_factors(intelligence_data)

            return {
                "risk_score": final_score,
                "ml_score": ml_score,
                "weighted_score": weighted_score["risk_score"],
                "risk_category": risk_category,
                "confidence": float(risk_prob),
                "risk_factors": risk_factors,
                "source_contributions": weighted_score["source_contributions"],
                "recommendations": self._generate_recommendations(
                    final_score, risk_factors
                ),
            }

        except Exception as e:
            self.logger.error(f"Error calculating risk score: {e}")
            return self._calculate_weighted_score(intelligence_data)

    def _calculate_weighted_score(self, intelligence_data: Dict) -> Dict:
        """Calculate risk score using weighted intelligence sources"""
        source_scores = {}
        source_contributions = {}

        for source, weight in self.source_weights.items():
            source_data = intelligence_data.get(source, {})

            if source == "domain_intel":
                score = self._calculate_domain_risk(source_data)
            elif source == "ip_intel":
                score = self._calculate_ip_risk(source_data)
            elif source == "email_intel":
                score = self._calculate_email_risk(source_data)
            elif source == "social_media":
                score = self._calculate_social_risk(source_data)
            elif source == "crypto_intel":
                score = source_data.get("risk_score", 50)
            elif source == "company_intel":
                score = self._calculate_company_risk(source_data)
            elif source == "flight_intel":
                score = source_data.get("anomaly_score", 50)
            elif source == "web_intel":
                score = self._calculate_web_risk(source_data)
            elif source == "threat_intel":
                score = self._calculate_threat_risk(source_data)
            else:
                score = 50

            source_scores[source] = score
            source_contributions[source] = score * weight

        # Calculate weighted average
        total_weight = sum(self.source_weights.values())
        weighted_score = sum(source_contributions.values()) / total_weight

        return {
            "risk_score": int(weighted_score),
            "source_contributions": source_contributions,
            "source_scores": source_scores,
        }

    def _calculate_domain_risk(self, domain_data: Dict) -> int:
        """Calculate domain-specific risk score"""
        score = 50

        if domain_data.get("age_days", 365) < 30:
            score += 20  # New domain
        if domain_data.get("privacy_enabled", False):
            score += 15  # Privacy protection
        if not domain_data.get("ssl_valid", True):
            score += 25  # Invalid SSL

        return min(score, 100)

    def _calculate_ip_risk(self, ip_data: Dict) -> int:
        """Calculate IP-specific risk score"""
        score = 50

        score += int(ip_data.get("geolocation_risk", 0.5) * 20)
        score += int(ip_data.get("asn_reputation", 0.5) * 20)
        score += ip_data.get("blacklist_count", 0) * 5

        if ip_data.get("is_vpn", False) or ip_data.get("is_tor", False):
            score += 30

        return min(score, 100)

    def _calculate_email_risk(self, email_data: Dict) -> int:
        """Calculate email-specific risk score"""
        score = 50

        score += int((1 - email_data.get("domain_reputation", 0.5)) * 30)
        score += int(email_data.get("bounce_rate", 0) * 20)
        score += int(email_data.get("spam_complaints", 0) * 50)

        return min(score, 100)

    def _calculate_social_risk(self, social_data: Dict) -> int:
        """Calculate social media risk score"""
        score = 50

        if not social_data.get("verified", False):
            score += 10

        ratio = social_data.get("followers_count", 0) / max(
            social_data.get("following_count", 1), 1
        )
        if ratio < 0.1:
            score += 15  # Low follower ratio

        if social_data.get("account_age_days", 365) < 30:
            score += 20  # New account

        return min(score, 100)

    def _calculate_company_risk(self, company_data: Dict) -> int:
        """Calculate company-specific risk score"""
        score = 50

        score += int(company_data.get("industry_risk", 0.5) * 30)
        score += int((1 - company_data.get("compliance_score", 0.5)) * 30)
        score += int((1 - company_data.get("financial_health", 0.5)) * 20)

        return min(score, 100)

    def _calculate_web_risk(self, web_data: Dict) -> int:
        """Calculate web-specific risk score"""
        score = 50

        score += int((1 - web_data.get("domain_reputation", 0.5)) * 30)
        score += int(web_data.get("content_risk", 0.5) * 20)

        if web_data.get("malware_detected", False):
            score += 50

        return min(score, 100)

    def _calculate_threat_risk(self, threat_data: Dict) -> int:
        """Calculate threat intelligence risk score"""
        score = 50

        score += int(threat_data.get("actor_association_score", 0.5) * 40)
        score += int(threat_data.get("malware_family_score", 0.5) * 30)
        score += threat_data.get("ioc_match_count", 0) * 10

        return min(score, 100)

    def _determine_risk_category(self, score: int) -> str:
        """Determine risk category based on score"""
        for category, config in self.risk_categories.items():
            if config["min_score"] <= score <= config["max_score"]:
                return category
        return "unknown"

    def _identify_risk_factors(self, intelligence_data: Dict) -> List[str]:
        """Identify key risk factors"""
        risk_factors = []

        # Domain factors
        domain_data = intelligence_data.get("domain_intel", {})
        if domain_data.get("age_days", 365) < 30:
            risk_factors.append("new_domain")
        if domain_data.get("privacy_enabled", False):
            risk_factors.append("domain_privacy")

        # IP factors
        ip_data = intelligence_data.get("ip_intel", {})
        if ip_data.get("blacklist_count", 0) > 0:
            risk_factors.append("ip_blacklisted")
        if ip_data.get("is_vpn", False):
            risk_factors.append("vpn_usage")

        # Crypto factors
        crypto_data = intelligence_data.get("crypto_intel", {})
        if crypto_data.get("risk_score", 50) > 70:
            risk_factors.append("high_crypto_risk")

        # Threat factors
        threat_data = intelligence_data.get("threat_intel", {})
        if threat_data.get("ioc_match_count", 0) > 5:
            risk_factors.append("multiple_ioc_matches")

        return risk_factors

    def _generate_recommendations(
        self, score: int, risk_factors: List[str]
    ) -> List[str]:
        """Generate investigation recommendations"""
        recommendations = []

        if score > 80:
            recommendations.append("URGENT: Immediate security investigation required")
        elif score > 60:
            recommendations.append("HIGH PRIORITY: Enhanced due diligence needed")

        if "new_domain" in risk_factors:
            recommendations.append("Verify domain registration legitimacy")

        if "domain_privacy" in risk_factors:
            recommendations.append("Investigate domain ownership through WHOIS")

        if "ip_blacklisted" in risk_factors:
            recommendations.append("Check IP reputation and blacklist status")

        if "vpn_usage" in risk_factors:
            recommendations.append("Verify legitimate VPN usage vs anonymity tools")

        if "high_crypto_risk" in risk_factors:
            recommendations.append(
                "Conduct detailed cryptocurrency transaction analysis"
            )

        if "multiple_ioc_matches" in risk_factors:
            recommendations.append("Correlate with known threat intelligence")

        return recommendations

    def save_model(self):
        """Save the trained model to disk"""
        try:
            model_data = {
                "ensemble": self.ensemble,
                "scaler": self.scaler,
                "feature_selector": self.feature_selector,
                "source_weights": self.source_weights,
                "risk_categories": self.risk_categories,
                "is_trained": self.is_trained,
                "trained_at": datetime.now().isoformat(),
            }

            joblib.dump(model_data, self.model_path)
            self.logger.info(f"Risk scoring model saved to {self.model_path}")

        except Exception as e:
            self.logger.error(f"Error saving risk model: {e}")

    def load_model(self):
        """Load a trained model from disk"""
        try:
            if not os.path.exists(self.model_path):
                self.logger.warning(f"Model file not found: {self.model_path}")
                return False

            model_data = joblib.load(self.model_path)

            self.ensemble = model_data["ensemble"]
            self.scaler = model_data["scaler"]
            self.feature_selector = model_data["feature_selector"]
            self.source_weights = model_data["source_weights"]
            self.risk_categories = model_data["risk_categories"]
            self.is_trained = model_data["is_trained"]

            self.logger.info(f"Risk scoring model loaded from {self.model_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error loading risk model: {e}")
            return False


# Global instance
risk_engine = RiskScoringEngine()


def calculate_comprehensive_risk(intelligence_data: Dict) -> Dict:
    """Convenience function for comprehensive risk calculation"""
    return risk_engine.calculate_risk_score(intelligence_data)
