#!/bin/bash
# OSINT Suite Monitoring Stack Startup Script

echo "🚀 Starting OSINT Suite Monitoring Stack..."

# Create necessary directories
mkdir -p monitoring/grafana/provisioning/datasources
mkdir -p monitoring/grafana/provisioning/dashboards
mkdir -p monitoring/grafana/dashboards

# Start monitoring stack
docker-compose -f docker-compose.monitoring.yml up -d

echo "📊 Monitoring Stack Components:"
echo "  • Prometheus: http://localhost:9090"
echo "  • Grafana: http://localhost:3000 (admin/osint2024!)"
echo "  • Node Exporter: http://localhost:9100"
echo "  • cAdvisor: http://localhost:8080"

echo ""
echo "🔧 To start the security metrics exporter:"
echo "  python security_metrics_exporter.py"

echo ""
echo "📈 Grafana Dashboard:"
echo "  • Security Monitoring Dashboard will be available at:"
echo "    http://localhost:3000/d/osint-security/security-monitoring"

echo ""
echo "✅ Monitoring stack started successfully!"