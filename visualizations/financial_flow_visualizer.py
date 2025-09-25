"""
Financial Flow Visualization
Interactive diagrams for cryptocurrency and financial transaction analysis
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots


class FinancialFlowVisualizer:
    """Visualization engine for financial and cryptocurrency flows"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Color schemes for transaction types
        self.transaction_colors = {
            'incoming': '#28a745',    # Green
            'outgoing': '#dc3545',    # Red
            'internal': '#6f42c1',    # Purple
            'exchange': '#ffc107',    # Yellow
            'mixer': '#fd7e14',       # Orange
            'unknown': '#6c757d'      # Gray
        }

        # Risk level colors
        self.risk_colors = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        }

    def create_transaction_flow_diagram(self, transactions: List[Dict]) -> go.Figure:
        """Create a sankey diagram showing transaction flows"""
        if not transactions:
            fig = go.Figure()
            fig.add_annotation(text="No transaction data available")
            return fig

        # Process transactions for sankey diagram
        nodes = []
        links = []
        node_indices = {}

        # Collect all unique addresses
        addresses = set()
        for tx in transactions:
            if 'from' in tx:
                addresses.add(tx['from'])
            if 'to' in tx:
                addresses.add(tx['to'])

        # Create nodes
        for i, addr in enumerate(sorted(addresses)):
            nodes.append(addr)
            node_indices[addr] = i

        # Create links
        for tx in transactions:
            if 'from' in tx and 'to' in tx and 'value' in tx:
                source = node_indices.get(tx['from'])
                target = node_indices.get(tx['to'])
                value = float(tx['value'])

                if source is not None and target is not None:
                    links.append({
                        'source': source,
                        'target': target,
                        'value': value,
                        'label': f"{value:.4f}"
                    })

        # Create sankey diagram
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=nodes,
                color="rgba(100, 149, 237, 0.8)"
            ),
            link=dict(
                source=[link['source'] for link in links],
                target=[link['target'] for link in links],
                value=[link['value'] for link in links],
                label=[link['label'] for link in links],
                color="rgba(150, 150, 150, 0.4)"
            )
        )])

        fig.update_layout(
            title="Cryptocurrency Transaction Flow",
            font_size=10,
            height=600
        )

        return fig

    def create_balance_timeline(self, balance_history: List[Dict]) -> go.Figure:
        """Create a timeline showing balance changes over time"""
        if not balance_history:
            fig = go.Figure()
            fig.add_annotation(text="No balance history available")
            return fig

        df = pd.DataFrame(balance_history)

        # Ensure timestamp column
        if 'timestamp' not in df.columns:
            df['timestamp'] = pd.date_range(
                start=datetime.now() - timedelta(days=len(df)),
                periods=len(df),
                freq='D'
            )

        df['timestamp'] = pd.to_datetime(df['timestamp'])

        fig = go.Figure()

        # Balance line
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df.get('balance', 0),
            mode='lines+markers',
            name='Balance',
            line=dict(color='blue', width=2),
            marker=dict(size=6),
            hovertemplate='%{x}<br>Balance: %{y:.4f}<extra></extra>'
        ))

        # Add transaction markers
        if 'transactions' in df.columns:
            for idx, row in df.iterrows():
                if row['transactions'] > 0:
                    fig.add_trace(go.Scatter(
                        x=[row['timestamp']],
                        y=[row['balance']],
                        mode='markers',
                        marker=dict(size=10, color='red', symbol='diamond'),
                        name='Transaction',
                        showlegend=idx == 0,
                        hovertemplate=f"Transaction: {row['transactions']}<extra></extra>"
                    ))

        fig.update_layout(
            title="Balance Timeline",
            xaxis_title="Date",
            yaxis_title="Balance",
            height=400,
            hovermode='x unified'
        )

        return fig

    def create_transaction_volume_chart(self, transactions: List[Dict]) -> go.Figure:
        """Create a chart showing transaction volume over time"""
        if not transactions:
            fig = go.Figure()
            fig.add_annotation(text="No transaction data available")
            return fig

        df = pd.DataFrame(transactions)

        # Ensure timestamp column
        if 'timestamp' not in df.columns:
            df['timestamp'] = pd.date_range(
                start=datetime.now() - timedelta(days=len(df)),
                periods=len(df),
                freq='H'
            )

        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Group by hour/day
        df['period'] = df['timestamp'].dt.floor('h')
        volume_by_period = df.groupby('period').agg({
            'value': 'sum',
            'timestamp': 'count'  # Count transactions by timestamp
        }).reset_index()

        volume_by_period.columns = ['period', 'total_value', 'transaction_count']

        # Create subplots
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Transaction Volume (Value)', 'Transaction Count'),
            shared_xaxes=True
        )

        # Volume chart
        fig.add_trace(
            go.Bar(
                x=volume_by_period['period'],
                y=volume_by_period['total_value'],
                name='Total Value',
                marker_color='lightblue'
            ),
            row=1, col=1
        )

        # Count chart
        fig.add_trace(
            go.Bar(
                x=volume_by_period['period'],
                y=volume_by_period['transaction_count'],
                name='Transaction Count',
                marker_color='lightgreen'
            ),
            row=2, col=1
        )

        fig.update_layout(
            height=600,
            showlegend=False,
            title="Transaction Volume Analysis"
        )

        fig.update_xaxes(title_text="Time Period", row=2, col=1)
        fig.update_yaxes(title_text="Total Value", row=1, col=1)
        fig.update_yaxes(title_text="Transaction Count", row=2, col=1)

        return fig

    def create_wallet_risk_heatmap(self, wallet_data: List[Dict]) -> go.Figure:
        """Create a heatmap showing wallet risk patterns"""
        if not wallet_data:
            fig = go.Figure()
            fig.add_annotation(text="No wallet data available")
            return fig

        df = pd.DataFrame(wallet_data)

        # Create risk categories
        risk_categories = ['Low', 'Medium', 'High', 'Critical']
        wallet_names = [f"Wallet {i+1}" for i in range(len(df))]

        # Create risk matrix
        risk_matrix = []
        for wallet in wallet_data:
            risk_score = wallet.get('risk_score', 50)
            if risk_score <= 25:
                risk_matrix.append([1, 0, 0, 0])  # Low
            elif risk_score <= 50:
                risk_matrix.append([0, 1, 0, 0])  # Medium
            elif risk_score <= 75:
                risk_matrix.append([0, 0, 1, 0])  # High
            else:
                risk_matrix.append([0, 0, 0, 1])  # Critical

        fig = go.Figure(data=go.Heatmap(
            z=risk_matrix,
            x=risk_categories,
            y=wallet_names,
            colorscale=[
                [0, 'rgba(40, 167, 69, 0.8)'],    # Green for Low
                [0.33, 'rgba(255, 193, 7, 0.8)'],  # Yellow for Medium
                [0.66, 'rgba(253, 126, 20, 0.8)'], # Orange for High
                [1, 'rgba(220, 53, 69, 0.8)']      # Red for Critical
            ],
            hoverongaps=False,
            hovertemplate='Wallet: %{y}<br>Risk Level: %{x}<br>Value: %{z}<extra></extra>'
        ))

        fig.update_layout(
            title="Wallet Risk Heatmap",
            xaxis_title="Risk Level",
            yaxis_title="Wallet",
            height=400
        )

        return fig

    def create_exchange_flow_network(self, exchange_data: Dict) -> go.Figure:
        """Create a network graph showing exchange connections"""
        if not exchange_data:
            fig = go.Figure()
            fig.add_annotation(text="No exchange data available")
            return fig

        G = nx.Graph()

        # Add exchange nodes
        exchanges = list(exchange_data.keys())
        for exchange in exchanges:
            G.add_node(exchange, type='exchange', size=20)

        # Add wallet nodes and connections
        wallet_count = 0
        for exchange, wallets in exchange_data.items():
            for wallet in wallets:
                wallet_node = f"Wallet_{wallet_count}"
                G.add_node(wallet_node, type='wallet', size=15)
                G.add_edge(exchange, wallet_node, weight=1)
                wallet_count += 1

        # Create positions
        pos = nx.spring_layout(G, k=2, iterations=50)

        # Create edge traces
        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=1, color='rgba(100,100,100,0.5)'),
            hoverinfo='none',
            mode='lines',
            showlegend=False
        )

        # Create node traces
        exchange_nodes = []
        wallet_nodes = []

        for node in G.nodes(data=True):
            x, y = pos[node[0]]
            if node[1]['type'] == 'exchange':
                exchange_nodes.append((x, y, node[0]))
            else:
                wallet_nodes.append((x, y, node[0]))

        # Exchange nodes
        if exchange_nodes:
            exchange_x, exchange_y, exchange_text = zip(*exchange_nodes)
            exchange_trace = go.Scatter(
                x=exchange_x,
                y=exchange_y,
                mode='markers+text',
                text=exchange_text,
                textposition="top center",
                marker=dict(size=25, color='red'),
                name='Exchanges',
                hoverinfo='text'
            )

        # Wallet nodes
        if wallet_nodes:
            wallet_x, wallet_y, wallet_text = zip(*wallet_nodes)
            wallet_trace = go.Scatter(
                x=wallet_x,
                y=wallet_y,
                mode='markers',
                marker=dict(size=15, color='blue'),
                name='Wallets',
                hoverinfo='text',
                text=wallet_text
            )

        # Create figure
        fig = go.Figure()

        fig.add_trace(edge_trace)
        if exchange_nodes:
            fig.add_trace(exchange_trace)
        if wallet_nodes:
            fig.add_trace(wallet_trace)

        fig.update_layout(
            title="Exchange-Wallet Connection Network",
            showlegend=True,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='white',
            height=500
        )

        return fig

    def create_financial_dashboard(self, financial_data: Dict) -> Dict[str, go.Figure]:
        """Create a comprehensive financial dashboard"""
        dashboard = {}

        # Transaction Flow Diagram
        if 'transactions' in financial_data:
            dashboard['transaction_flow'] = self.create_transaction_flow_diagram(
                financial_data['transactions']
            )

        # Balance Timeline
        if 'balance_history' in financial_data:
            dashboard['balance_timeline'] = self.create_balance_timeline(
                financial_data['balance_history']
            )

        # Transaction Volume
        if 'transactions' in financial_data:
            dashboard['transaction_volume'] = self.create_transaction_volume_chart(
                financial_data['transactions']
            )

        # Wallet Risk Heatmap
        if 'wallets' in financial_data:
            dashboard['wallet_risk'] = self.create_wallet_risk_heatmap(
                financial_data['wallets']
            )

        # Exchange Network
        if 'exchanges' in financial_data:
            dashboard['exchange_network'] = self.create_exchange_flow_network(
                financial_data['exchanges']
            )

        return dashboard

# Convenience functions
def create_transaction_flow(transactions: List[Dict]) -> go.Figure:
    """Convenience function for transaction flow diagram"""
    visualizer = FinancialFlowVisualizer()
    return visualizer.create_transaction_flow_diagram(transactions)

def create_balance_chart(balance_history: List[Dict]) -> go.Figure:
    """Convenience function for balance timeline"""
    visualizer = FinancialFlowVisualizer()
    return visualizer.create_balance_timeline(balance_history)

def create_financial_dashboard(financial_data: Dict) -> Dict[str, go.Figure]:
    """Convenience function for financial dashboard"""
    visualizer = FinancialFlowVisualizer()
    return visualizer.create_financial_dashboard(financial_data)