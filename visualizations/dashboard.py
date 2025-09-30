"""
OSINT Intelligence Dashboard
Web-based dashboard for comprehensive intelligence visualization
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, dash_table, dcc, html
from dash.exceptions import PreventUpdate
from financial_flow_visualizer import FinancialFlowVisualizer

# Import visualization modules
from intelligence_visualizer import IntelligenceVisualizer


class OSINTDashboard:
    """Comprehensive web dashboard for OSINT intelligence"""

    def __init__(self, data_manager=None):
        self.logger = logging.getLogger(__name__)
        self.data_manager = data_manager

        # Initialize visualizers
        self.intel_visualizer = IntelligenceVisualizer()
        self.financial_visualizer = FinancialFlowVisualizer()

        # Initialize Dash app
        self.app = dash.Dash(
            __name__,
            external_stylesheets=[dbc.themes.DARKLY],
            suppress_callback_exceptions=True,
        )

        # Dashboard data
        self.current_data = {}
        self.risk_thresholds = {"low": 30, "medium": 60, "high": 80, "critical": 100}

        self.setup_layout()
        self.setup_callbacks()

    def setup_layout(self):
        """Setup the dashboard layout"""
        self.app.layout = dbc.Container(
            [
                # Header
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                html.H1(
                                    "OSINT Intelligence Dashboard",
                                    className="text-center text-primary mb-4",
                                ),
                                html.P(
                                    "Comprehensive intelligence analysis and risk assessment platform",
                                    className="text-center text-muted mb-4",
                                ),
                            ]
                        )
                    ]
                ),
                # Control Panel
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardHeader("Control Panel"),
                                        dbc.CardBody(
                                            [
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                html.Label(
                                                                    "Risk Thresholds"
                                                                ),
                                                                dcc.RangeSlider(
                                                                    id="risk-threshold-slider",
                                                                    min=0,
                                                                    max=100,
                                                                    step=5,
                                                                    value=[30, 60, 80],
                                                                    marks={
                                                                        0: "0",
                                                                        25: "25",
                                                                        50: "50",
                                                                        75: "75",
                                                                        100: "100",
                                                                    },
                                                                    tooltip={
                                                                        "placement": "bottom",
                                                                        "always_visible": True,
                                                                    },
                                                                ),
                                                            ],
                                                            width=6,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                html.Label(
                                                                    "Time Range"
                                                                ),
                                                                dcc.DatePickerRange(
                                                                    id="date-range-picker",
                                                                    start_date=datetime.now()
                                                                    - timedelta(
                                                                        days=30
                                                                    ),
                                                                    end_date=datetime.now(),
                                                                    display_format="YYYY-MM-DD",
                                                                ),
                                                            ],
                                                            width=6,
                                                        ),
                                                    ]
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dbc.Button(
                                                                    "Refresh Data",
                                                                    id="refresh-btn",
                                                                    color="primary",
                                                                    className="mt-3",
                                                                ),
                                                                dbc.Button(
                                                                    "Export Report",
                                                                    id="export-btn",
                                                                    color="secondary",
                                                                    className="mt-3 ml-2",
                                                                ),
                                                            ]
                                                        )
                                                    ]
                                                ),
                                            ]
                                        ),
                                    ]
                                )
                            ]
                        )
                    ],
                    className="mb-4",
                ),
                # Key Metrics Row
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardBody(
                                            [
                                                html.H4(
                                                    "Overall Risk Score",
                                                    className="card-title text-center",
                                                ),
                                                dcc.Graph(
                                                    id="overall-risk-gauge",
                                                    style={"height": "300px"},
                                                ),
                                            ]
                                        )
                                    ]
                                )
                            ],
                            width=4,
                        ),
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardBody(
                                            [
                                                html.H4(
                                                    "Active Intelligence Sources",
                                                    className="card-title text-center",
                                                ),
                                                html.H2(
                                                    id="active-sources-count",
                                                    className="text-center text-primary",
                                                ),
                                                html.P(
                                                    "Sources providing data",
                                                    className="text-center text-muted",
                                                ),
                                            ]
                                        )
                                    ]
                                )
                            ],
                            width=4,
                        ),
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardBody(
                                            [
                                                html.H4(
                                                    "High Risk Alerts",
                                                    className="card-title text-center",
                                                ),
                                                html.H2(
                                                    id="high-risk-count",
                                                    className="text-center text-danger",
                                                ),
                                                html.P(
                                                    "Entities requiring attention",
                                                    className="text-center text-muted",
                                                ),
                                            ]
                                        )
                                    ]
                                )
                            ],
                            width=4,
                        ),
                    ],
                    className="mb-4",
                ),
                # Main Visualization Tabs
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.Tabs(
                                    [
                                        dbc.Tab(
                                            [
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="intelligence-network",
                                                                    style={
                                                                        "height": "500px"
                                                                    },
                                                                )
                                                            ],
                                                            width=8,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="source-contributions",
                                                                    style={
                                                                        "height": "500px"
                                                                    },
                                                                )
                                                            ],
                                                            width=4,
                                                        ),
                                                    ]
                                                )
                                            ],
                                            label="Intelligence Network",
                                            tab_id="network-tab",
                                        ),
                                        dbc.Tab(
                                            [
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="timeline-analysis",
                                                                    style={
                                                                        "height": "400px"
                                                                    },
                                                                )
                                                            ]
                                                        )
                                                    ]
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="risk-distribution",
                                                                    style={
                                                                        "height": "300px"
                                                                    },
                                                                )
                                                            ]
                                                        )
                                                    ]
                                                ),
                                            ],
                                            label="Timeline & Risk Analysis",
                                            tab_id="timeline-tab",
                                        ),
                                        dbc.Tab(
                                            [
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="transaction-flow",
                                                                    style={
                                                                        "height": "500px"
                                                                    },
                                                                )
                                                            ],
                                                            width=6,
                                                        ),
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="balance-timeline",
                                                                    style={
                                                                        "height": "500px"
                                                                    },
                                                                )
                                                            ],
                                                            width=6,
                                                        ),
                                                    ]
                                                ),
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="wallet-risk-heatmap",
                                                                    style={
                                                                        "height": "400px"
                                                                    },
                                                                )
                                                            ]
                                                        )
                                                    ]
                                                ),
                                            ],
                                            label="Financial Analysis",
                                            tab_id="financial-tab",
                                        ),
                                        dbc.Tab(
                                            [
                                                dbc.Row(
                                                    [
                                                        dbc.Col(
                                                            [
                                                                dcc.Graph(
                                                                    id="geographic-map",
                                                                    style={
                                                                        "height": "500px"
                                                                    },
                                                                )
                                                            ]
                                                        )
                                                    ]
                                                )
                                            ],
                                            label="Geographic View",
                                            tab_id="geographic-tab",
                                        ),
                                    ],
                                    id="main-tabs",
                                    active_tab="network-tab",
                                )
                            ]
                        )
                    ],
                    className="mb-4",
                ),
                # Data Table
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                dbc.Card(
                                    [
                                        dbc.CardHeader("Intelligence Data Table"),
                                        dbc.CardBody(
                                            [
                                                dcc.Loading(
                                                    id="loading-table",
                                                    children=[
                                                        dash_table.DataTable(
                                                            id="intelligence-table",
                                                            columns=[],
                                                            data=[],
                                                            page_size=10,
                                                            style_table={
                                                                "overflowX": "auto"
                                                            },
                                                            style_cell={
                                                                "textAlign": "left",
                                                                "padding": "10px",
                                                                "backgroundColor": "#2c3034",
                                                                "color": "white",
                                                            },
                                                            style_header={
                                                                "backgroundColor": "#1a1e22",
                                                                "fontWeight": "bold",
                                                                "color": "white",
                                                            },
                                                            style_data_conditional=[
                                                                {
                                                                    "if": {
                                                                        "column_id": "risk_score",
                                                                        "filter_query": "{risk_score} > 80",
                                                                    },
                                                                    "backgroundColor": "#dc3545",
                                                                    "color": "white",
                                                                },
                                                                {
                                                                    "if": {
                                                                        "column_id": "risk_score",
                                                                        "filter_query": "{risk_score} > 60 && {risk_score} <= 80",
                                                                    },
                                                                    "backgroundColor": "#fd7e14",
                                                                    "color": "white",
                                                                },
                                                            ],
                                                        )
                                                    ],
                                                )
                                            ]
                                        ),
                                    ]
                                )
                            ]
                        )
                    ]
                ),
                # Footer
                dbc.Row(
                    [
                        dbc.Col(
                            [
                                html.Hr(),
                                html.P(
                                    "OSINT Intelligence Dashboard - Real-time analysis and risk assessment",
                                    className="text-center text-muted",
                                ),
                                html.P(
                                    f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                                    className="text-center text-muted",
                                ),
                            ]
                        )
                    ]
                ),
            ],
            fluid=True,
            style={"backgroundColor": "#1a1e22"},
        )

    def setup_callbacks(self):
        """Setup Dash callbacks for interactivity"""

        @self.app.callback(
            [
                Output("overall-risk-gauge", "figure"),
                Output("active-sources-count", "children"),
                Output("high-risk-count", "children"),
                Output("intelligence-network", "figure"),
                Output("source-contributions", "figure"),
                Output("timeline-analysis", "figure"),
                Output("risk-distribution", "figure"),
                Output("transaction-flow", "figure"),
                Output("balance-timeline", "figure"),
                Output("wallet-risk-heatmap", "figure"),
                Output("geographic-map", "figure"),
                Output("intelligence-table", "columns"),
                Output("intelligence-table", "data"),
            ],
            [Input("refresh-btn", "n_clicks"), Input("main-tabs", "active_tab")],
        )
        def update_dashboard(n_clicks, active_tab):
            """Update all dashboard components"""
            if n_clicks is None:
                raise PreventUpdate

            # Load current intelligence data
            intelligence_data = self.load_intelligence_data()

            # Create visualizations
            risk_gauge = self.intel_visualizer.create_risk_score_gauge(
                intelligence_data.get("overall_risk", {}).get("risk_score", 50)
            )

            network_graph = self.intel_visualizer.create_intelligence_network_graph(
                intelligence_data
            )

            source_contributions = (
                self.intel_visualizer.create_source_contribution_chart(
                    intelligence_data.get("source_contributions", {})
                )
            )

            timeline = self.intel_visualizer.create_timeline_analysis(
                intelligence_data.get("temporal_events", [])
            )

            risk_dist = self.intel_visualizer.create_risk_distribution_chart(
                intelligence_data.get("risk_scores", [])
            )

            # Financial visualizations
            transaction_flow = (
                self.financial_visualizer.create_transaction_flow_diagram(
                    intelligence_data.get("financial", {}).get("transactions", [])
                )
            )

            balance_timeline = self.financial_visualizer.create_balance_timeline(
                intelligence_data.get("financial", {}).get("balance_history", [])
            )

            wallet_heatmap = self.financial_visualizer.create_wallet_risk_heatmap(
                intelligence_data.get("financial", {}).get("wallets", [])
            )

            # Geographic visualization
            geo_map = self.intel_visualizer.create_geographic_visualization(
                intelligence_data.get("geo_data", [])
            )

            # Calculate metrics
            active_sources = len(
                [k for k, v in intelligence_data.items() if isinstance(v, dict) and v]
            )
            high_risk_count = len(
                [
                    r
                    for r in intelligence_data.get("risk_scores", [])
                    if r.get("risk_score", 0) > 80
                ]
            )

            # Create data table
            table_data = self.prepare_table_data(intelligence_data)
            table_columns = self.create_table_columns(table_data)

            return (
                risk_gauge,
                active_sources,
                high_risk_count,
                network_graph,
                source_contributions,
                timeline,
                risk_dist,
                transaction_flow,
                balance_timeline,
                wallet_heatmap,
                geo_map,
                table_columns,
                table_data,
            )

        @self.app.callback(
            Output("export-btn", "children"), [Input("export-btn", "n_clicks")]
        )
        def export_report(n_clicks):
            """Export dashboard report"""
            if n_clicks is None:
                raise PreventUpdate

            # Export functionality would be implemented here
            self.logger.info("Exporting dashboard report...")
            return "Report Exported!"

    def load_intelligence_data(self) -> Dict:
        """Load intelligence data from data manager or create sample data"""
        if self.data_manager:
            return self.data_manager.get_all_intelligence_data()
        else:
            # Return sample data for demonstration
            return self.create_sample_data()

    def create_sample_data(self) -> Dict:
        """Create sample intelligence data for demonstration"""
        return {
            "overall_risk": {"risk_score": 65, "confidence": 0.85},
            "domain_intel": {
                "age_days": 365,
                "ssl_valid": True,
                "subdomains": ["api", "admin", "blog"],
            },
            "ip_intel": {
                "blacklist_count": 2,
                "geolocation_risk": 0.3,
                "open_ports": [80, 443, 22],
            },
            "email_intel": {"domain_reputation": 0.7, "bounce_rate": 0.02},
            "social_media": {
                "verified": True,
                "followers_count": 15000,
                "engagement_rate": 0.05,
            },
            "crypto_intel": {
                "risk_score": 45,
                "balance": 25.5,
                "transaction_count": 150,
            },
            "company_intel": {"industry_risk": 0.4, "compliance_score": 0.8},
            "flight_intel": {"anomaly_score": 35, "flight_count": 25},
            "web_intel": {"domain_reputation": 0.6, "malware_detected": False},
            "threat_intel": {"ioc_match_count": 3, "actor_association_score": 0.2},
            "source_contributions": {
                "domain_intel": 15,
                "ip_intel": 12,
                "email_intel": 10,
                "social_media": 8,
                "crypto_intel": 15,
                "company_intel": 12,
                "flight_intel": 10,
                "web_intel": 8,
                "threat_intel": 10,
            },
            "temporal_events": [
                {
                    "timestamp": datetime.now() - timedelta(days=i),
                    "event_type": "transaction" if i % 3 == 0 else "login",
                    "description": f"Event {i}",
                }
                for i in range(30)
            ],
            "risk_scores": [
                {
                    "entity": f"Entity_{i}",
                    "risk_score": 20 + i * 3,
                    "category": "low" if i < 10 else "medium" if i < 20 else "high",
                }
                for i in range(30)
            ],
            "financial": {
                "transactions": [
                    {
                        "from": "addr1",
                        "to": "addr2",
                        "value": 1.5,
                        "timestamp": datetime.now(),
                    },
                    {
                        "from": "addr2",
                        "to": "addr3",
                        "value": 2.1,
                        "timestamp": datetime.now(),
                    },
                    {
                        "from": "addr3",
                        "to": "addr1",
                        "value": 0.8,
                        "timestamp": datetime.now(),
                    },
                ],
                "balance_history": [
                    {
                        "timestamp": datetime.now() - timedelta(days=i),
                        "balance": 100 + i * 2,
                        "transactions": i % 5,
                    }
                    for i in range(30)
                ],
                "wallets": [
                    {"name": f"Wallet_{i}", "risk_score": 20 + i * 3} for i in range(10)
                ],
            },
            "geo_data": [
                {
                    "lat": 40.7128 + i * 0.1,
                    "lon": -74.0060 + i * 0.1,
                    "name": f"Location_{i}",
                    "risk_score": 30 + i * 5,
                    "risk_category": "low" if i < 5 else "medium",
                }
                for i in range(10)
            ],
        }

    def prepare_table_data(self, intelligence_data: Dict) -> List[Dict]:
        """Prepare data for the intelligence table"""
        table_data = []

        # Add risk scores
        for risk_item in intelligence_data.get("risk_scores", []):
            table_data.append(
                {
                    "type": "Risk Assessment",
                    "entity": risk_item.get("entity", "Unknown"),
                    "risk_score": risk_item.get("risk_score", 0),
                    "category": risk_item.get("category", "unknown"),
                    "timestamp": datetime.now().isoformat(),
                }
            )

        # Add temporal events
        for event in intelligence_data.get("temporal_events", []):
            table_data.append(
                {
                    "type": "Event",
                    "entity": event.get("event_type", "Unknown"),
                    "risk_score": 0,
                    "category": "event",
                    "timestamp": event.get("timestamp", datetime.now()).isoformat(),
                }
            )

        return table_data

    def create_table_columns(self, table_data: List[Dict]) -> List[Dict]:
        """Create table columns based on data"""
        if not table_data:
            return []

        columns = []
        sample_row = table_data[0]

        for key in sample_row.keys():
            columns.append({"name": key.replace("_", " ").title(), "id": key})

        return columns

    def run_server(self, host: str = "0.0.0.0", port: int = 8050, debug: bool = False):
        """Run the dashboard server"""
        self.logger.info(f"Starting OSINT Dashboard on {host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)


# Convenience function to create and run dashboard
def create_dashboard(
    data_manager=None, host: str = "0.0.0.0", port: int = 8050, debug: bool = False
):
    """Create and run the OSINT intelligence dashboard"""
    dashboard = OSINTDashboard(data_manager)
    dashboard.run_server(host=host, port=port, debug=debug)


if __name__ == "__main__":
    # Run dashboard with sample data
    create_dashboard(debug=True)
