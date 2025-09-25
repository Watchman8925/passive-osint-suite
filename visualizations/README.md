# Advanced Visualizations for OSINT Suite

This module provides comprehensive visualization capabilities for intelligence analysis, risk assessment, and data exploration in the OSINT suite.

## Components Overview

### 1. Intelligence Visualizer (`intelligence_visualizer.py`)
- **Risk Score Gauges**: Interactive gauge charts showing risk levels with color-coded thresholds
- **Intelligence Network Graphs**: Interactive network diagrams showing correlations between intelligence sources
- **Timeline Analysis**: Temporal visualization of intelligence events and activities
- **Risk Distribution Charts**: Histograms and distribution plots of risk scores
- **Source Contribution Charts**: Pie charts showing contribution of different intelligence sources
- **Geographic Visualizations**: Interactive maps showing intelligence data by location

### 2. Financial Flow Visualizer (`financial_flow_visualizer.py`)
- **Transaction Flow Diagrams**: Sankey diagrams showing cryptocurrency transaction flows
- **Balance Timelines**: Time-series charts showing balance changes over time
- **Transaction Volume Analysis**: Bar charts showing transaction volume and frequency
- **Wallet Risk Heatmaps**: Heatmaps showing risk patterns across multiple wallets
- **Exchange Network Graphs**: Network diagrams showing connections between exchanges and wallets

### 3. Interactive Dashboard (`dashboard.py`)
- **Comprehensive Web Interface**: Full-featured Dash-based dashboard
- **Real-time Updates**: Live data refresh and interactive controls
- **Multi-tab Interface**: Organized views for different types of analysis
- **Data Tables**: Interactive tables with filtering and sorting
- **Export Capabilities**: Report generation and data export features

## Installation

```bash
cd visualizations
pip install -r requirements.txt
```

## Usage

### Basic Visualizations

```python
from visualizations.intelligence_visualizer import IntelligenceVisualizer
from visualizations.financial_flow_visualizer import FinancialFlowVisualizer

# Initialize visualizers
intel_viz = IntelligenceVisualizer()
financial_viz = FinancialFlowVisualizer()

# Create risk gauge
risk_gauge = intel_viz.create_risk_score_gauge(75, "Domain Risk")

# Create network graph
network_graph = intel_viz.create_intelligence_network_graph({
    'domain_intel': {'age_days': 365},
    'ip_intel': {'blacklist_count': 2},
    'crypto_intel': {'risk_score': 45}
})

# Create transaction flow diagram
transaction_flow = financial_viz.create_transaction_flow_diagram([
    {'from': 'addr1', 'to': 'addr2', 'value': 1.5},
    {'from': 'addr2', 'to': 'addr3', 'value': 2.1}
])
```

### Interactive Dashboard

```python
from visualizations.dashboard import create_dashboard

# Run dashboard with sample data
create_dashboard(debug=True)

# Or with custom data manager
from your_data_manager import DataManager
data_manager = DataManager()
create_dashboard(data_manager=data_manager, port=8051)
```

### Advanced Usage

```python
# Create comprehensive dashboard
intel_data = {
    'overall_risk': {'risk_score': 65},
    'domain_intel': {'age_days': 365, 'ssl_valid': True},
    'ip_intel': {'blacklist_count': 2},
    'source_contributions': {'domain': 15, 'ip': 12, 'email': 10},
    'temporal_events': [...],
    'risk_scores': [...],
    'geo_data': [...]
}

dashboard = intel_viz.create_comprehensive_dashboard(intel_data)

# Export visualizations
intel_viz.export_visualization(risk_gauge, 'risk_report.html', 'html')
intel_viz.export_visualization(network_graph, 'network.png', 'png')
```

## Dashboard Features

### Control Panel
- **Risk Thresholds**: Adjustable sliders for risk level definitions
- **Time Range Selection**: Date pickers for temporal filtering
- **Data Refresh**: Real-time data updates
- **Report Export**: Generate and download analysis reports

### Key Metrics
- **Overall Risk Score**: Primary risk gauge with color coding
- **Active Sources**: Count of intelligence sources providing data
- **High Risk Alerts**: Number of entities requiring immediate attention

### Visualization Tabs

#### Intelligence Network Tab
- Interactive network graph showing intelligence correlations
- Source contribution pie chart
- Real-time updates based on data changes

#### Timeline & Risk Analysis Tab
- Event timeline with activity patterns
- Risk score distribution histogram
- Temporal trend analysis

#### Financial Analysis Tab
- Transaction flow sankey diagrams
- Balance change timelines
- Wallet risk heatmaps
- Exchange connection networks

#### Geographic View Tab
- Interactive maps with risk overlays
- Location-based intelligence clustering
- Geographic pattern analysis

### Data Table
- **Interactive Filtering**: Filter by risk level, source, or time
- **Sorting**: Sort by any column
- **Conditional Formatting**: Color-coded risk levels
- **Pagination**: Handle large datasets efficiently

## Data Formats

### Intelligence Data Structure
```python
{
    'overall_risk': {'risk_score': 65, 'confidence': 0.85},
    'domain_intel': {
        'age_days': 365,
        'ssl_valid': True,
        'subdomains': ['api', 'admin']
    },
    'ip_intel': {
        'blacklist_count': 2,
        'geolocation_risk': 0.3
    },
    'source_contributions': {
        'domain_intel': 15,
        'ip_intel': 12,
        'email_intel': 10
    },
    'temporal_events': [
        {
            'timestamp': '2024-01-15T10:30:00Z',
            'event_type': 'transaction',
            'description': 'Large value transfer'
        }
    ],
    'risk_scores': [
        {
            'entity': 'example.com',
            'risk_score': 75,
            'category': 'high'
        }
    ]
}
```

### Financial Data Structure
```python
{
    'transactions': [
        {
            'from': '1A2B3C...',
            'to': '4D5E6F...',
            'value': 1.5,
            'timestamp': '2024-01-15T10:30:00Z'
        }
    ],
    'balance_history': [
        {
            'timestamp': '2024-01-15T10:30:00Z',
            'balance': 100.5,
            'transactions': 3
        }
    ],
    'wallets': [
        {
            'name': 'Primary Wallet',
            'risk_score': 45
        }
    ]
}
```

## Customization

### Color Schemes
```python
# Custom risk colors
intel_viz.risk_colors = {
    'low': '#28a745',
    'medium': '#ffc107',
    'high': '#fd7e14',
    'critical': '#dc3545'
}

# Custom source colors
intel_viz.source_colors = {
    'domain': '#007bff',
    'ip': '#6f42c1',
    'email': '#e83e8c'
}
```

### Layout Customization
```python
# Custom dashboard layout
dashboard.app.layout = dbc.Container([
    # Your custom layout here
], fluid=True)
```

## Performance Optimization

### Large Datasets
- **Pagination**: Handle large tables efficiently
- **Lazy Loading**: Load data on demand
- **Sampling**: Use data sampling for real-time updates
- **Caching**: Cache expensive computations

### Real-time Updates
- **WebSocket Integration**: For live data streaming
- **Background Processing**: Async data processing
- **Incremental Updates**: Update only changed components

## Integration with OSINT Suite

### API Integration
```python
# Connect to OSINT API
from osint_api import OSINTAPI
api = OSINTAPI()

# Get intelligence data
intelligence_data = api.get_intelligence_data()

# Create visualizations
dashboard = intel_viz.create_comprehensive_dashboard(intelligence_data)
```

### Database Integration
```python
# Connect to intelligence database
from database import IntelligenceDatabase
db = IntelligenceDatabase()

# Query data for visualization
risk_data = db.get_risk_scores(time_range='30d')
timeline_data = db.get_temporal_events()

# Create specific visualizations
risk_chart = intel_viz.create_risk_distribution_chart(risk_data)
timeline_chart = intel_viz.create_timeline_analysis(timeline_data)
```

## Security Considerations

- **Data Sanitization**: Clean data before visualization
- **Access Control**: Implement user-based access controls
- **Audit Logging**: Log all visualization access and exports
- **Data Encryption**: Encrypt sensitive data in transit and at rest

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Port Conflicts**
   ```python
   create_dashboard(port=8051)  # Use different port
   ```

3. **Large Data Performance**
   ```python
   # Implement data sampling
   sampled_data = data.sample(n=1000)
   ```

4. **Memory Issues**
   ```python
   # Use data chunking
   for chunk in pd.read_csv('large_file.csv', chunksize=1000):
       process_chunk(chunk)
   ```

## Contributing

When adding new visualizations:
1. Follow the established pattern in existing visualizers
2. Include comprehensive documentation
3. Add error handling and data validation
4. Update the dashboard integration
5. Test with various data formats

## License

These visualizations are part of the OSINT suite and follow the same licensing terms.