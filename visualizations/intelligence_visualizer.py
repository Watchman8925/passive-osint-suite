"""
Advanced Visualizations for OSINT Intelligence
Interactive charts, graphs, and dashboards for intelligence analysis
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots


class IntelligenceVisualizer:
    """Advanced visualization engine for OSINT intelligence data"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Color schemes for different risk levels
        self.risk_colors = {
            "low": "#28a745",  # Green
            "medium": "#ffc107",  # Yellow
            "high": "#fd7e14",  # Orange
            "critical": "#dc3545",  # Red
        }

        # Intelligence source colors
        self.source_colors = {
            "domain": "#007bff",
            "ip": "#6f42c1",
            "email": "#e83e8c",
            "social": "#20c997",
            "crypto": "#fd7e14",
            "company": "#6c757d",
            "flight": "#17a2b8",
            "web": "#28a745",
            "threat": "#dc3545",
        }

    def create_risk_score_gauge(
        self, risk_score: int, title: str = "Risk Score"
    ) -> go.Figure:
        """Create a gauge chart for risk score visualization"""
        # Determine risk category
        if risk_score <= 30:
            category = "Low Risk"
            color = self.risk_colors["low"]
        elif risk_score <= 60:
            category = "Medium Risk"
            color = self.risk_colors["medium"]
        elif risk_score <= 80:
            category = "High Risk"
            color = self.risk_colors["high"]
        else:
            category = "Critical Risk"
            color = self.risk_colors["critical"]

        fig = go.Figure(
            go.Indicator(
                mode="gauge+number+delta",
                value=risk_score,
                domain={"x": [0, 1], "y": [0, 1]},
                title={
                    "text": f"{title}<br><span style='font-size:0.8em;color:gray'>{category}</span>"
                },
                delta={"reference": 50, "increasing": {"color": color}},
                gauge={
                    "axis": {
                        "range": [0, 100],
                        "tickwidth": 1,
                        "tickcolor": "darkblue",
                    },
                    "bar": {"color": color},
                    "bgcolor": "white",
                    "borderwidth": 2,
                    "bordercolor": "gray",
                    "steps": [
                        {"range": [0, 30], "color": "rgba(40, 167, 69, 0.3)"},
                        {"range": [30, 60], "color": "rgba(255, 193, 7, 0.3)"},
                        {"range": [60, 80], "color": "rgba(253, 126, 20, 0.3)"},
                        {"range": [80, 100], "color": "rgba(220, 53, 69, 0.3)"},
                    ],
                    "threshold": {
                        "line": {"color": "red", "width": 4},
                        "thickness": 0.75,
                        "value": 80,
                    },
                },
            )
        )

        fig.update_layout(
            font={"color": "darkblue", "family": "Arial"},
            paper_bgcolor="white",
            height=300,
        )

        return fig

    def create_intelligence_network_graph(self, intelligence_data: Dict) -> go.Figure:
        """Create an interactive network graph showing intelligence correlations"""
        G = nx.Graph()

        # Add nodes for different intelligence sources
        sources = []
        for source, data in intelligence_data.items():
            if isinstance(data, dict) and data:
                sources.append(source)
                G.add_node(
                    source,
                    type="source",
                    size=20,
                    color=self.source_colors.get(source, "#6c757d"),
                )

        # Add connections based on shared entities
        entities = defaultdict(list)

        # Extract entities from each source
        for source, data in intelligence_data.items():
            if not isinstance(data, dict):
                continue

            # Domain entities
            if "domain" in str(data).lower():
                entities["domains"].append(source)

            # IP entities
            if "ip" in str(data).lower() or "address" in str(data).lower():
                entities["ips"].append(source)

            # Email entities
            if "email" in str(data).lower():
                entities["emails"].append(source)

            # Crypto entities
            if "crypto" in source or "wallet" in str(data).lower():
                entities["crypto"].append(source)

            # Company entities
            if "company" in source or "business" in str(data).lower():
                entities["companies"].append(source)

        # Create edges based on shared entities
        for entity_type, source_list in entities.items():
            if len(source_list) > 1:
                for i in range(len(source_list)):
                    for j in range(i + 1, len(source_list)):
                        G.add_edge(
                            source_list[i],
                            source_list[j],
                            weight=1,
                            entity_type=entity_type,
                        )

        # Create positions for nodes
        pos = nx.spring_layout(G, k=2, iterations=50)

        # Create edge traces
        edge_traces = []
        for edge in G.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]

            edge_trace = go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                line=dict(width=2, color="rgba(100,100,100,0.5)"),
                hoverinfo="text",
                text=f"Connection: {edge[2]['entity_type']}",
                mode="lines",
                showlegend=False,
            )
            edge_traces.append(edge_trace)

        # Create node trace
        node_x = []
        node_y = []
        node_text = []
        node_color = []

        for node in G.nodes(data=True):
            x, y = pos[node[0]]
            node_x.append(x)
            node_y.append(y)
            node_text.append(f"{node[0]}<br>Type: {node[1]['type']}")
            node_color.append(node[1]["color"])

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            hoverinfo="text",
            text=node_text,
            textposition="top center",
            marker=dict(size=30, color=node_color, line_width=2, line_color="white"),
            showlegend=False,
        )

        # Create the figure
        fig = go.Figure(data=edge_traces + [node_trace])

        fig.update_layout(
            title="Intelligence Correlation Network",
            title_x=0.5,
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor="white",
            height=500,
        )

        return fig

    def create_timeline_analysis(self, temporal_data: List[Dict]) -> go.Figure:
        """Create a timeline visualization for intelligence events"""
        if not temporal_data:
            # Create empty figure with message
            fig = go.Figure()
            fig.add_annotation(
                text="No temporal data available",
                xref="paper",
                yref="paper",
                x=0.5,
                y=0.5,
                showarrow=False,
                font=dict(size=16),
            )
            return fig

        # Convert to DataFrame for easier processing
        df = pd.DataFrame(temporal_data)

        # Ensure we have timestamp column
        if "timestamp" not in df.columns:
            df["timestamp"] = pd.date_range(
                start=datetime.now() - timedelta(days=30), periods=len(df), freq="D"
            )

        df["timestamp"] = pd.to_datetime(df["timestamp"])

        # Create subplots
        fig = make_subplots(
            rows=2,
            cols=1,
            subplot_titles=("Intelligence Events Timeline", "Activity Volume"),
            row_heights=[0.7, 0.3],
        )

        # Timeline scatter plot
        if "event_type" in df.columns:
            for event_type in df["event_type"].unique():
                mask = df["event_type"] == event_type
                fig.add_trace(
                    go.Scatter(
                        x=df[mask]["timestamp"],
                        y=[event_type] * len(df[mask]),
                        mode="markers",
                        name=event_type,
                        marker=dict(size=10),
                        hovertemplate="%{x}<br>Event: %{text}<extra></extra>",
                        text=df[mask].get("description", ""),
                    ),
                    row=1,
                    col=1,
                )
        else:
            fig.add_trace(
                go.Scatter(
                    x=df["timestamp"],
                    y=[0] * len(df),
                    mode="markers",
                    name="Events",
                    marker=dict(size=10, color="blue"),
                    hovertemplate="%{x}<extra></extra>",
                ),
                row=1,
                col=1,
            )

        # Activity volume (daily count)
        daily_counts = df.groupby(df["timestamp"].dt.date).size().reset_index()
        daily_counts.columns = ["date", "count"]

        fig.add_trace(
            go.Bar(
                x=daily_counts["date"],
                y=daily_counts["count"],
                name="Daily Activity",
                marker_color="lightblue",
            ),
            row=2,
            col=1,
        )

        fig.update_layout(height=600, showlegend=True, hovermode="x unified")

        fig.update_xaxes(title_text="Date", row=1, col=1)
        fig.update_xaxes(title_text="Date", row=2, col=1)
        fig.update_yaxes(title_text="Event Type", row=1, col=1)
        fig.update_yaxes(title_text="Activity Count", row=2, col=1)

        return fig

    def create_risk_distribution_chart(self, risk_scores: List[Dict]) -> go.Figure:
        """Create a distribution chart of risk scores"""
        if not risk_scores:
            fig = go.Figure()
            fig.add_annotation(
                text="No risk score data available",
                xref="paper",
                yref="paper",
                x=0.5,
                y=0.5,
                showarrow=False,
            )
            return fig

        df = pd.DataFrame(risk_scores)

        # Create histogram
        fig = go.Figure()

        fig.add_trace(
            go.Histogram(
                x=df.get("risk_score", []),
                nbinsx=20,
                name="Risk Scores",
                marker_color="rgba(100, 149, 237, 0.7)",
                opacity=0.7,
            )
        )

        # Add vertical lines for risk categories
        for threshold, label in [(30, "Low"), (60, "Medium"), (80, "High")]:
            fig.add_vline(
                x=threshold,
                line_dash="dash",
                line_color="red",
                annotation_text=f"{label} Risk Threshold",
                annotation_position="top",
            )

        fig.update_layout(
            title="Risk Score Distribution",
            xaxis_title="Risk Score",
            yaxis_title="Frequency",
            bargap=0.1,
            height=400,
        )

        return fig

    def create_source_contribution_chart(self, source_contributions: Dict) -> go.Figure:
        """Create a pie chart showing intelligence source contributions"""
        if not source_contributions:
            fig = go.Figure()
            fig.add_annotation(text="No source contribution data available")
            return fig

        # Prepare data
        sources = list(source_contributions.keys())
        contributions = list(source_contributions.values())

        # Create colors for sources
        colors = [
            self.source_colors.get(source.split("_")[0], "#6c757d")
            for source in sources
        ]

        fig = go.Figure(
            data=[
                go.Pie(
                    labels=sources,
                    values=contributions,
                    marker_colors=colors,
                    textinfo="label+percent",
                    insidetextorientation="radial",
                    hovertemplate="<b>%{label}</b><br>Contribution: %{value:.1f}<br>Percentage: %{percent}<extra></extra>",
                )
            ]
        )

        fig.update_layout(
            title="Intelligence Source Contributions to Risk Score",
            height=400,
            showlegend=True,
        )

        return fig

    def create_geographic_visualization(self, geo_data: List[Dict]) -> go.Figure:
        """Create geographic visualization of intelligence data"""
        if not geo_data:
            fig = go.Figure()
            fig.add_annotation(text="No geographic data available")
            return fig

        df = pd.DataFrame(geo_data)

        # Ensure we have lat/lon columns
        if "lat" not in df.columns or "lon" not in df.columns:
            fig = go.Figure()
            fig.add_annotation(text="Geographic coordinates not available")
            return fig

        fig = px.scatter_mapbox(
            df,
            lat="lat",
            lon="lon",
            hover_name=df.get("name", "Location"),
            hover_data=["risk_score"] if "risk_score" in df.columns else [],
            color=df.get("risk_category", "unknown"),
            color_discrete_map={
                "low": self.risk_colors["low"],
                "medium": self.risk_colors["medium"],
                "high": self.risk_colors["high"],
                "critical": self.risk_colors["critical"],
                "unknown": "#6c757d",
            },
            zoom=3,
            height=500,
        )

        fig.update_layout(
            mapbox_style="open-street-map", title="Geographic Intelligence Distribution"
        )

        return fig

    def create_comprehensive_dashboard(
        self, intelligence_data: Dict
    ) -> Dict[str, go.Figure]:
        """Create a comprehensive dashboard with multiple visualizations"""
        dashboard = {}

        # Risk Score Gauge
        if "overall_risk" in intelligence_data:
            dashboard["risk_gauge"] = self.create_risk_score_gauge(
                intelligence_data["overall_risk"].get("risk_score", 50),
                "Overall Intelligence Risk",
            )

        # Intelligence Network Graph
        dashboard["network_graph"] = self.create_intelligence_network_graph(
            intelligence_data
        )

        # Timeline Analysis
        if "temporal_events" in intelligence_data:
            dashboard["timeline"] = self.create_timeline_analysis(
                intelligence_data["temporal_events"]
            )

        # Risk Distribution
        if "risk_scores" in intelligence_data:
            dashboard["risk_distribution"] = self.create_risk_distribution_chart(
                intelligence_data["risk_scores"]
            )

        # Source Contributions
        if "source_contributions" in intelligence_data:
            dashboard["source_contributions"] = self.create_source_contribution_chart(
                intelligence_data["source_contributions"]
            )

        # Geographic Visualization
        if "geo_data" in intelligence_data:
            dashboard["geographic"] = self.create_geographic_visualization(
                intelligence_data["geo_data"]
            )

        return dashboard

    def export_visualization(
        self, fig: go.Figure, filename: str, format: str = "html"
    ) -> str:
        """Export visualization to file"""
        if format == "html":
            fig.write_html(filename)
        elif format == "png":
            fig.write_image(filename)
        elif format == "svg":
            fig.write_image(filename, format="svg")
        elif format == "pdf":
            fig.write_image(filename, format="pdf")

        return filename


# Convenience functions
def create_risk_gauge(risk_score: int, title: str = "Risk Score") -> go.Figure:
    """Convenience function for creating risk gauge"""
    visualizer = IntelligenceVisualizer()
    return visualizer.create_risk_score_gauge(risk_score, title)


def create_network_graph(intelligence_data: Dict) -> go.Figure:
    """Convenience function for creating network graph"""
    visualizer = IntelligenceVisualizer()
    return visualizer.create_intelligence_network_graph(intelligence_data)


def create_comprehensive_dashboard(intelligence_data: Dict) -> Dict[str, go.Figure]:
    """Convenience function for creating full dashboard"""
    visualizer = IntelligenceVisualizer()
    return visualizer.create_comprehensive_dashboard(intelligence_data)
