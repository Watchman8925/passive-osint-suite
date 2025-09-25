# Machine Learning Models for OSINT Suite

This directory contains machine learning models for advanced intelligence analysis and risk assessment in the OSINT suite.

## Models Overview

### 1. Cryptocurrency Pattern Detector (`crypto_pattern_detector.py`)
- **Purpose**: Detects suspicious patterns in cryptocurrency transactions and wallet behavior
- **Features**:
  - Transaction pattern analysis
  - Balance volatility assessment
  - Exchange connection monitoring
  - Privacy tool usage detection
  - Anomaly detection using Isolation Forest
- **Use Case**: Identify potentially fraudulent or high-risk crypto addresses

### 2. Flight Anomaly Detector (`flight_anomaly_detector.py`)
- **Purpose**: Detects suspicious flight patterns and potential security threats
- **Features**:
  - Route analysis and deviation detection
  - Aircraft type risk assessment
  - Weather condition impact analysis
  - Temporal pattern recognition
  - Clustering-based anomaly detection
- **Use Case**: Monitor aviation activities for security concerns

### 3. Risk Scoring Engine (`risk_scoring_engine.py`)
- **Purpose**: Combines multiple intelligence sources for comprehensive risk assessment
- **Features**:
  - Ensemble machine learning approach
  - Multi-source intelligence integration
  - Weighted risk scoring
  - Feature importance analysis
  - Automated recommendations generation
- **Use Case**: Generate holistic risk profiles from diverse intelligence data

## Installation

```bash
cd ml_models
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from ml_models import ml_manager

# Load all trained models
ml_manager.load_all_models()

# Analyze cryptocurrency address
crypto_result = ml_manager.analyze_crypto_address({
    'balance': 100.5,
    'transaction_count': 150,
    'exchanges': ['Binance', 'Coinbase'],
    'transactions': [...]
})

# Analyze flight data
flight_result = ml_manager.analyze_flight_anomaly({
    'departure': {'code': 'JFK', 'lat': 40.6413, 'lon': -73.7781},
    'arrival': {'code': 'LAX', 'lat': 33.9425, 'lon': -118.4081},
    'aircraft': {'type': 'B737'},
    'departure_time': '2024-01-15T10:30:00Z',
    ...
})

# Calculate comprehensive risk
risk_result = ml_manager.calculate_comprehensive_risk({
    'domain_intel': {...},
    'ip_intel': {...},
    'crypto_intel': crypto_result,
    'flight_intel': flight_result,
    ...
})
```

### Advanced Usage

```python
# Train models with custom data
ml_manager.train_crypto_detector(training_data, labels)
ml_manager.train_flight_detector(training_data, labels)
ml_manager.train_risk_engine(training_data, labels)

# Save trained models
ml_manager.save_all_models()

# Get model performance metrics
metrics = ml_manager.get_model_metrics()

# Health check
health_report = ml_manager.get_model_health_report()
```

## Model Training

### Training Data Format

#### Cryptocurrency Data
```python
{
    'balance': float,
    'transaction_count': int,
    'avg_transaction_value': float,
    'unique_counterparties': int,
    'first_seen': str,  # ISO format
    'last_seen': str,   # ISO format
    'exchanges': list,
    'transactions': list
}
```

#### Flight Data
```python
{
    'departure': {'code': str, 'lat': float, 'lon': float},
    'arrival': {'code': str, 'lat': float, 'lon': float},
    'departure_time': str,  # ISO format
    'arrival_time': str,    # ISO format
    'aircraft': {'type': str},
    'passenger_count': int,
    'weather': dict
}
```

#### Intelligence Data (for Risk Engine)
```python
{
    'domain_intel': dict,
    'ip_intel': dict,
    'email_intel': dict,
    'social_media': dict,
    'crypto_intel': dict,
    'company_intel': dict,
    'flight_intel': dict,
    'web_intel': dict,
    'threat_intel': dict,
    'temporal': dict
}
```

## Model Evaluation

### Performance Metrics
- **Accuracy**: Overall prediction accuracy
- **Precision**: True positive rate
- **Recall**: Ability to find all positive instances
- **F1-Score**: Harmonic mean of precision and recall
- **AUC-ROC**: Area under the receiver operating characteristic curve

### Feature Importance
Each model provides feature importance scores to understand which factors contribute most to predictions.

## Model Persistence

Models are automatically saved to the `ml_models/` directory with `.pkl` extension:
- `crypto_pattern_detector.pkl`
- `flight_anomaly_detector.pkl`
- `risk_scoring_engine.pkl`

## Integration with OSINT Suite

These models integrate with the main OSINT suite through:

1. **API Endpoints**: RESTful endpoints for real-time analysis
2. **Batch Processing**: Background processing for large datasets
3. **Dashboard Integration**: Visual representation of risk scores
4. **Alert System**: Automated alerts based on risk thresholds

## Security Considerations

- Models are trained on anonymized data only
- No personally identifiable information is stored
- All predictions include confidence scores
- Regular model retraining with updated threat intelligence

## Maintenance

### Regular Tasks
1. **Model Retraining**: Monthly retraining with new data
2. **Performance Monitoring**: Track accuracy and false positive rates
3. **Feature Updates**: Add new intelligence sources as available
4. **Version Control**: Maintain model version history

### Health Checks
```python
# Get comprehensive health report
health = ml_manager.get_model_health_report()
print(f"Overall health: {health['overall_health']}")
print(f"Recommendations: {health['recommendations']}")
```

## Troubleshooting

### Common Issues
1. **Model not loading**: Check file permissions and paths
2. **Poor predictions**: Verify input data format and quality
3. **Memory errors**: Reduce batch size for large datasets
4. **Training failures**: Check data quality and feature engineering

### Performance Optimization
- Use GPU acceleration for large models
- Implement model quantization for edge deployment
- Cache frequently used predictions
- Use async processing for real-time analysis

## Contributing

When adding new models:
1. Follow the established pattern in existing models
2. Include comprehensive documentation
3. Add unit tests and integration tests
4. Update the manager class
5. Document training data requirements

## License

These models are part of the OSINT suite and follow the same licensing terms.