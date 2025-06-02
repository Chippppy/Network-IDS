import streamlit as st
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import os
from collections import Counter

# Set page config
st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
    <style>
    .alert-box {
        padding: 8px;
        border-radius: 5px;
        margin: 3px 0;
    }
    .alert-high {
        background-color: rgba(255, 0, 0, 0.1);
        border-left: 5px solid red;
    }
    .alert-medium {
        background-color: rgba(255, 165, 0, 0.1);
        border-left: 5px solid orange;
    }
    .alert-low {
        background-color: rgba(255, 255, 0, 0.1);
        border-left: 5px solid yellow;
    }
    .attack-type-header {
        font-weight: bold;
        margin-top: 10px;
        margin-bottom: 3px;
        padding: 3px;
        background-color: rgba(0, 0, 0, 0.05);
        border-radius: 3px;
    }
    div.block-container {
        padding-top: 2rem;
        padding-bottom: 0rem;
    }
    div.stMetric {
        padding: 10px 0px;
    }
    section.main > div {
        padding-top: 0rem;
    }
    div[data-testid="stHorizontalBlock"] {
        padding: 0px;
        margin-bottom: -1rem;
    }
    h1 {
        margin-bottom: 0px;
    }
    h3 {
        margin-top: 0.5rem;
    }
    div[data-testid="stSidebarUserContent"] {
        padding-top: 0rem;
    }
    .plot-container {
        margin-bottom: -2rem;
    }
    </style>
""", unsafe_allow_html=True)

def load_data():
    """Load the latest data from the JSON files"""
    packet_stats = {'total_packets': 0, 'tcp_packets': 0, 'udp_packets': 0, 'other_packets': 0}
    alerts = []
    
    try:
        if os.path.exists('data/packet_stats.json'):
            with open('data/packet_stats.json', 'r') as f:
                packet_stats = json.load(f)
        
        if os.path.exists('data/alerts.json'):
            with open('data/alerts.json', 'r') as f:
                alerts = json.load(f)
    except Exception as e:
        st.error(f"Error loading data: {str(e)}")
    
    return packet_stats, alerts

def filter_alerts(alerts, severity_filter):
    """Filter alerts based on selected severity"""
    if severity_filter == "All":
        return alerts
    return [alert for alert in alerts if alert.get('severity', '').lower() == severity_filter.lower()]

def group_alerts_by_type(alerts):
    """Group alerts by attack type"""
    attack_types = {}
    for alert in alerts:
        alert_type = alert.get('type', 'Unknown')
        if alert_type not in attack_types:
            attack_types[alert_type] = []
        attack_types[alert_type].append(alert)
    return attack_types

def create_attack_distribution_chart(alerts):
    """Create a pie chart showing distribution of attack types"""
    if not alerts:
        return None
    
    attack_counts = Counter(alert.get('type', 'Unknown') for alert in alerts)
    
    fig = go.Figure(data=[go.Pie(
        labels=list(attack_counts.keys()),
        values=list(attack_counts.values()),
        hole=.3
    )])
    
    fig.update_layout(
        title="Attack Type Distribution",
        showlegend=True,
        height=300,
        margin=dict(t=30, b=0, l=0, r=0),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5
        )
    )
    
    return fig

def create_protocol_distribution_chart(packet_stats):
    """Create a pie chart for protocol distribution"""
    fig = go.Figure(data=[go.Pie(
        labels=['TCP', 'UDP', 'Other'],
        values=[packet_stats.get('tcp_packets', 0),
               packet_stats.get('udp_packets', 0),
               packet_stats.get('other_packets', 0)],
        hole=.3
    )])
    
    fig.update_layout(
        title="Protocol Distribution",
        showlegend=True,
        height=300,
        margin=dict(t=30, b=0, l=0, r=0),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5
        )
    )
    
    return fig

def create_traffic_figure(df):
    """Create a line chart for traffic data"""
    if df.empty:
        return None
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['tcp_packets'],
        name='TCP Packets',
        mode='lines'
    ))
    
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['udp_packets'],
        name='UDP Packets',
        mode='lines'
    ))
    
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['other_packets'],
        name='Other Packets',
        mode='lines'
    ))
    
    fig.update_layout(
        title="Packet Traffic Over Time",
        xaxis_title="Time",
        yaxis_title="Packet Count",
        height=300,
        margin=dict(t=30, b=30, l=50, r=20),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        hovermode='x unified'
    )
    
    return fig

def main():
    # Header
    st.title("🛡️ Network IDS Dashboard")
    
    # Initialize session state for historical data
    if 'historical_data' not in st.session_state:
        st.session_state.historical_data = []
    
    while True:
        # Load the latest data
        packet_stats, alerts = load_data()
        
        # Update historical data with current timestamp
        current_data = {
            'timestamp': datetime.now(),
            'tcp_packets': packet_stats.get('tcp_packets', 0),
            'udp_packets': packet_stats.get('udp_packets', 0),
            'other_packets': packet_stats.get('other_packets', 0)
        }
        
        st.session_state.historical_data.append(current_data)
        
        # Keep only last 100 data points
        if len(st.session_state.historical_data) > 100:
            st.session_state.historical_data.pop(0)
        
        # Create main layout with two columns (70-30 split)
        col1, col2 = st.columns([7, 3])
        
        with col1:
            # Metrics row
            metrics_cols = st.columns(4)
            with metrics_cols[0]:
                st.metric("Total Packets", packet_stats.get('total_packets', 0))
            with metrics_cols[1]:
                st.metric("TCP Packets", packet_stats.get('tcp_packets', 0))
            with metrics_cols[2]:
                st.metric("UDP Packets", packet_stats.get('udp_packets', 0))
            with metrics_cols[3]:
                st.metric("Other Packets", packet_stats.get('other_packets', 0))
            
            # Traffic Over Time Line Chart
            df_historical = pd.DataFrame(st.session_state.historical_data)
            if not df_historical.empty:
                fig_line = create_traffic_figure(df_historical)
                if fig_line:
                    st.plotly_chart(fig_line, use_container_width=True)
            
            # Distribution charts in two columns
            dist_col1, dist_col2 = st.columns(2)
            with dist_col1:
                fig_protocol = create_protocol_distribution_chart(packet_stats)
                st.plotly_chart(fig_protocol, use_container_width=True)
            
            with dist_col2:
                if alerts:
                    fig_attacks = create_attack_distribution_chart(alerts)
                    if fig_attacks:
                        st.plotly_chart(fig_attacks, use_container_width=True)
        
        with col2:
            # Alerts Section with Severity Filter
            st.subheader("⚠️ Recent Alerts")
            
            # Add severity filter
            severity_options = ["All", "High", "Medium", "Low"]
            selected_severity = st.selectbox(
                "Filter by Severity",
                severity_options,
                key="severity_filter"
            )
            
            # Filter and group alerts
            filtered_alerts = filter_alerts(alerts, selected_severity)
            
            if filtered_alerts:
                grouped_alerts = group_alerts_by_type(filtered_alerts)
                
                for attack_type, alerts_of_type in grouped_alerts.items():
                    st.markdown(f"""
                        <div class="attack-type-header">
                            {attack_type} ({len(alerts_of_type)})
                        </div>
                    """, unsafe_allow_html=True)
                    
                    for alert in reversed(alerts_of_type):
                        severity = alert.get('severity', 'Low').lower()
                        st.markdown(f"""
                            <div class="alert-box alert-{severity}">
                                <strong>{alert.get('type')}</strong><br>
                                {alert.get('details')}<br>
                                <small>{alert.get('timestamp')}</small>
                            </div>
                        """, unsafe_allow_html=True)
            else:
                if selected_severity == "All":
                    st.info("No alerts detected")
                else:
                    st.info(f"No {selected_severity} severity alerts detected")
        
        # Update every 2 seconds
        time.sleep(2)
        st.rerun()

if __name__ == "__main__":
    main() 