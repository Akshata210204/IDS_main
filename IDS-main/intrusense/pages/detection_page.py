import streamlit as st
import pandas as pd
import time
import altair as alt
import streamlit.components.v1 as components
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import numpy as np

from common.sidebar import render_user_sidebar
from common.session import require_login
from common.detection_utlis import detect_severity
from common.live_capture import live_packet_stream
from common.log_utils import start_new_session, save_log


# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Intrusion Detection System", 
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# ---------------- AUTH ----------------
require_login()
render_user_sidebar()

PROTOCOL_MAP = {
    1: "TCP",
    2: "UDP",
    3: "ICMP"
}
SEVERITY_MAP = {
    "Informational": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5
}
# ---------------- SESSION STATE INIT ----------------
if "live_running" not in st.session_state:
    st.session_state.live_running = False
if "live_index" not in st.session_state:
    st.session_state.live_index = 0
if "live_generator" not in st.session_state:
    st.session_state.live_generator = None
if "chart_data" not in st.session_state:
    st.session_state.chart_data = pd.DataFrame(
        columns=["packet", "severity", "attack_class", "confidence"]
    )
if st.session_state.get("_last_page") != "detection":
    st.session_state.live_running = False
    st.session_state.live_generator = None

if "stream_busy" not in st.session_state:
    st.session_state.stream_busy = False

st.session_state["_last_page"] = "detection"

if "live_packets_df" not in st.session_state:
    st.session_state.live_packets_df = pd.DataFrame(
        columns=[
            "packet",
            "duration",
            "protocol_type",
            "service",
            "flag",
            "src_bytes",
            "dst_bytes",
            "land",
            "count",
            "srv_count",
            "serror_rate",
            "srv_serror_rate",
            "rerror_rate",
            "srv_rerror_rate",
            "same_srv_rate",
            "diff_srv_rate",
            "srv_diff_host_rate",
            "dst_host_count",
            "dst_host_srv_count",
            "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate",
            "dst_host_serror_rate",
            "dst_host_srv_serror_rate",
            "dst_host_rerror_rate",
            "dst_host_srv_rerror_rate",
            "attack_name",
            "attack_class",
            "severity",
            "confidence"
        ]
    )

if "alert_count" not in st.session_state:
    st.session_state.alert_count = 0
if "high_count" not in st.session_state:
    st.session_state.high_count = 0
if "medium_count" not in st.session_state:
    st.session_state.medium_count = 0
if "low_count" not in st.session_state:
    st.session_state.low_count = 0

# ================= CUSTOM CSS =================
st.markdown("""
<style>
/* Import Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

/* Global Styles */
.stApp {
    font-family: 'Inter', sans-serif;
    background: linear-gradient(135deg, #667eea0d 0%, #764ba20d 100%);
}

/* Main Container */
.main-container {
    width: 100%;
    margin: 0;
    padding: 1rem;
}

/* Header Styles */
.glass-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 2rem 2.5rem;
    border-radius: 30px;
    margin-bottom: 2rem;
    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
    position: relative;
    overflow: hidden;
    width: 100%;
}

.glass-header::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
    animation: rotate 20s linear infinite;
}

@keyframes rotate {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

.header-title {
    font-size: 2.8rem;
    font-weight: 800;
    color: white;
    margin-bottom: 0.5rem;
    letter-spacing: -1px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
}

.header-subtitle {
    font-size: 1.1rem;
    color: rgba(255,255,255,0.9);
    font-weight: 400;
}

.header-badge {
    background: rgba(255,255,255,0.2);
    backdrop-filter: blur(10px);
    padding: 0.5rem 1.5rem;
    border-radius: 50px;
    color: white;
    font-size: 0.9rem;
    display: inline-block;
    margin-top: 1rem;
}

/* Control Panel */
.control-panel {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    margin-bottom: 2rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.05);
    border: 1px solid rgba(102,126,234,0.1);
    width: 100%;
}
h3:contains("Final Statistics") {
    margin-bottom: 0.5rem !important;
}
/* Stats Cards - Full Width */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 0.5 rem;
    margin: 2rem 0;
    width: 100%;
}

.stat-card {
    background: white;
    padding: 1.5rem;
    border-radius: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.05);
    border: 1px solid rgba(102,126,234,0.1);
    transition: all 0.3s ease;
    width: 100%;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 20px 40px rgba(102,126,234,0.15);
}

.stat-icon {
    width: 50px;
    height: 50px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    border-radius: 15px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 1rem;
    color: white;
    font-size: 1.5rem;
}

.stat-value {
    font-size: 2rem;
    font-weight: 700;
    color: #1e293b;
    line-height: 1.2;
}

.stat-label {
    font-size: 0.9rem;
    color: #64748b;
    font-weight: 500;
}

.stat-change {
    font-size: 0.8rem;
    margin-top: 0.5rem;
    padding: 0.25rem 0.75rem;
    border-radius: 50px;
    display: inline-block;
}

.stat-change.positive {
    background: #22c55e20;
    color: #22c55e;
}

.stat-change.negative {
    background: #ef444420;
    color: #ef4444;
}
.stat-change {
    font-size: 0.8rem;
    margin-top: 0.5rem;
    padding: 0.25rem 0.75rem;
    border-radius: 50px;
    display: inline-block;
}

.stat-change.positive {
    background: #22c55e20;
    color: #22c55e;
}

.stat-change.negative {
    background: #ef444420;
    color: #ef4444;
}

.stat-change.info {
    background: #64748b20;
    color: #64748b;
}

.stat-change.low {
    background: #22c55e20;
    color: #22c55e;
}

.stat-change.medium {
    background: #f59e0b20;
    color: #f59e0b;
}

.stat-change.high {
    background: #ef444420;
    color: #ef4444;
}

.stat-change.critical {
    background: #7f1d1d20;
    color: #7f1d1d;
}

/* Chart Container - Full Width */
.chart-container {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    margin: 2rem 0;
    box-shadow: 0 10px 30px rgba(0,0,0,0.05);
    width: 100%;
}

/* Alert Cards */
.alert-card {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    border-left: 6px solid;
    box-shadow: 0 10px 30px rgba(0,0,0,0.05);
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.alert-card:hover {
    transform: translateX(5px);
    box-shadow: 0 15px 40px rgba(0,0,0,0.1);
}

.alert-card.high {
    border-left-color: #ef4444;
    background: linear-gradient(90deg, #ef444405, white);
}

.alert-card.medium {
    border-left-color: #f59e0b;
    background: linear-gradient(90deg, #f59e0b05, white);
}

.alert-card.low {
    border-left-color: #22c55e;
    background: linear-gradient(90deg, #22c55e05, white);
}

.alert-title {
    font-size: 1.2rem;
    font-weight: 600;
    color: #1e293b;
    margin-bottom: 0.5rem;
}

.alert-meta {
    display: flex;
    gap: 1.5rem;
    color: #64748b;
    font-size: 0.9rem;
    margin-bottom: 1rem;
}

.alert-progress {
    height: 8px;
    background: #f1f5f9;
    border-radius: 10px;
    overflow: hidden;
}

.alert-progress-fill {
    height: 100%;
    border-radius: 10px;
    transition: width 0.5s ease;
}

/* Buttons */
.stButton > button {
    border-radius: 12px !important;
    font-weight: 600 !important;
    font-size: 0.95rem !important;
    padding: 0.6rem 1.5rem !important;
    transition: all 0.3s ease !important;
    border: none !important;
    width: 100%;
}

.stButton > button:first-child {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
    color: white !important;
    box-shadow: 0 10px 20px rgba(102,126,234,0.3) !important;
}

.stButton > button:first-child:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 15px 30px rgba(102,126,234,0.4) !important;
}

.stButton > button:last-child {
    background: #f1f5f9 !important;
    color: #64748b !important;
}

.stButton > button:last-child:hover {
    background: #e2e8f0 !important;
    color: #475569 !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 2rem;
    background: white;
    padding: 0.5rem;
    border-radius: 50px;
    margin-bottom: 2rem;
    width: 100%;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 50px !important;
    padding: 0.75rem 2rem !important;
    font-weight: 600 !important;
    color: #64748b !important;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
    color: white !important;
}

/* Metrics */
div[data-testid="metric-container"] {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.05);
    border: 1px solid rgba(102,126,234,0.1);
    width: 100%;
}

/* Footer */
.footer {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1.5rem;
    border-radius: 20px;
    color: white;
    text-align: center;
    margin-top: 3rem;
    font-size: 0.95rem;
    width: 100%;
}

/* Animations */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.live-indicator {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(239,68,68,0.1);
    color: #ef4444;
    padding: 0.5rem 1rem;
    border-radius: 50px;
    font-size: 0.9rem;
    font-weight: 600;
}

.live-dot {
    width: 10px;
    height: 10px;
    background: #ef4444;
    border-radius: 50%;
    animation: pulse 1.5s infinite;
}

/* Progress Bar */
.progress-container {
    background: #f1f5f9;
    border-radius: 10px;
    height: 10px;
    overflow: hidden;
}

.progress-bar {
    height: 100%;
    border-radius: 10px;
    background: linear-gradient(90deg, #667eea, #764ba2);
    transition: width 0.5s ease;
}

/* Remove any width constraints */
.block-container {
    max-width: 100% !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
}

/* Responsive */
@media (max-width: 1200px) {
    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (max-width: 768px) {
    .header-title {
        font-size: 2rem;
    }
    
    .stats-grid {
        grid-template-columns: 1fr;
    }
}

/* ================= TABLE DROPDOWN STYLES ================= */
.feature-table-container {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    margin: 1.5rem 0;
    box-shadow: 0 10px 30px rgba(0,0,0,0.05);
    border: 1px solid rgba(102,126,234,0.1);
}

.feature-table-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    cursor: pointer;
    padding: 0.5rem;
    border-radius: 10px;
    transition: all 0.3s ease;
}

.feature-table-header:hover {
    background: #f8fafc;
}

.feature-table-title {
    font-size: 1.2rem;
    font-weight: 600;
    color: #1e293b;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.feature-table-title::before {
    content: '📊';
    font-size: 1.4rem;
}

.feature-table-toggle {
    color: #667eea;
    font-size: 1.2rem;
    transition: transform 0.3s ease;
}

.feature-table-toggle.open {
    transform: rotate(180deg);
}

/* Category Tabs */
.feature-category-tabs {
    display: flex;
    gap: 0.5rem;
    margin: 1rem 0;
    flex-wrap: wrap;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 0.5rem;
}

.feature-category-tab {
    padding: 0.5rem 1.2rem;
    border-radius: 30px;
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    background: #f1f5f9;
    color: #64748b;
    border: none;
}

.feature-category-tab:hover {
    background: #e2e8f0;
    color: #475569;
}

.feature-category-tab.active {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    box-shadow: 0 5px 15px rgba(102,126,234,0.3);
}

/* Excel-like Table */
.excel-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    overflow: hidden;
}

.excel-table th {
    background: #f8fafc;
    color: #475569;
    font-weight: 600;
    padding: 0.8rem;
    text-align: left;
    border-bottom: 2px solid #e2e8f0;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.excel-table td {
    padding: 0.6rem 0.8rem;
    border-bottom: 1px solid #e2e8f0;
    color: #1e293b;
}

.excel-table tr:hover {
    background: #f1f5f9;
}

.excel-table tr:last-child td {
    border-bottom: none;
}

/* Feature value styling */
.feature-value-badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 500;
}

.feature-value-badge.high {
    background: #ef444420;
    color: #ef4444;
}

.feature-value-badge.medium {
    background: #f59e0b20;
    color: #f59e0b;
}

.feature-value-badge.low {
    background: #22c55e20;
    color: #22c55e;
}

.feature-value-badge.info {
    background: #64748b20;
    color: #64748b;
}

.feature-value-badge.critical {
    background: #7f1d1d20;
    color: #7f1d1d;
}

/* Feature Grid */
.feature-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.8rem;
    margin-top: 1rem;
}

.feature-grid-item {
    background: #f8fafc;
    border-radius: 10px;
    padding: 0.8rem;
    border: 1px solid #e2e8f0;
    transition: all 0.2s ease;
}

.feature-grid-item:hover {
    transform: translateY(-2px);
    border-color: #667eea;
    box-shadow: 0 5px 15px rgba(102,126,234,0.1);
}

.feature-grid-label {
    font-size: 0.7rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 0.3rem;
}

.feature-grid-value {
    font-size: 1rem;
    font-weight: 600;
    color: #1e293b;
    font-family: monospace;
}

/* Column Selector */
.column-selector {
    background: #f8fafc;
    border-radius: 12px;
    padding: 1rem;
    margin: 1rem 0;
    border: 1px solid #e2e8f0;
}

.column-selector-title {
    font-size: 0.9rem;
    font-weight: 600;
    color: #475569;
    margin-bottom: 0.8rem;
}

.column-selector-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
}

.column-selector-item {
    padding: 0.3rem 0.8rem;
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 20px;
    font-size: 0.8rem;
    cursor: pointer;
    transition: all 0.2s ease;
}

.column-selector-item:hover {
    border-color: #667eea;
    background: #667eea10;
}

.column-selector-item.selected {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
}
.stats-grid {
    margin-top: 0.5rem !important;
    margin-bottom: 1rem !important;
}
/* Export Button */
.export-btn-table {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
    border: none;
    padding: 0.6rem 1.5rem;
    border-radius: 10px;
    font-weight: 600;
    font-size: 0.9rem;
    cursor: pointer;
    transition: all 0.3s ease;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 1rem;
}

.export-btn-table:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(16,185,129,0.3);
}

/* Packet Selector Dropdown */
.packet-selector-dropdown {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 1rem;
    margin-bottom: 1.5rem;
}
/* Equal height cards */
.equal-height-cards {
    display: flex;
    height: 100%;
}

.card-left, .card-right {
    height: 100%;
    min-height: 380px;  /* Fixed minimum height for both cards */
    display: flex;
    flex-direction: column;
}

.card-left {
    justify-content: space-between;
}

.card-right {
    justify-content: center;
}

/* Gauge container */
.gauge-container {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    height: 100%;
    min-height: 300px;
}

/* Mini stats fix */
.mini-stats {
    display: flex;
    justify-content: space-around;
    margin-top: 1rem;
    padding: 0.75rem;
    background: #f8fafc;
    border-radius: 10px;
    width: 100%;
}
</style>
""", unsafe_allow_html=True)

# ================= HEADER =================
st.markdown(f"""
<div class="glass-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <div class="header-title">Intrusion Detection System</div>
            <div class="header-subtitle">Real-time Network Threat Monitoring & Analysis</div>
            <div class="header-badge">
                <span>Secure Connection</span> • 
                <span>Live Monitoring</span> • 
                <span>Real-time Alerts</span>
            </div>
        </div>
        <div style="text-align: right; color: white;">
            <div style="font-size: 1rem; opacity: 0.9;">{datetime.now().strftime('%B %d, %Y')}</div>
            <div style="font-size: 1.5rem; font-weight: 700;">{datetime.now().strftime('%I:%M %p')}</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ================= CONTROL PANEL =================
st.markdown('<div class="control-panel">', unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns([1, 1, 2, 1])

with col1:
    if st.button("Start Live Detection", use_container_width=True):
        st.session_state.live_running = True
        st.session_state.live_generator = live_packet_stream()
        st.session_state.chart_data = pd.DataFrame(
            columns=["packet", "severity", "attack_class", "confidence"]
        )
        st.session_state.live_packets_df = pd.DataFrame(
            columns=st.session_state.live_packets_df.columns
        )
        st.session_state.current_log_file = start_new_session(
            st.session_state.get("email")
        )
        st.session_state.alert_count = 0
        st.session_state.high_count = 0
        st.session_state.medium_count = 0
        st.session_state.low_count = 0
        st.rerun()

with col2:
    if st.button("Stop Stream", use_container_width=True):
        st.session_state.live_running = False
        st.session_state.live_generator = None
        st.rerun()

with col3:
    if st.session_state.live_running:
        st.markdown("""
        <div class="live-indicator">
            <span class="live-dot"></span>
            <span>LIVE DETECTION ACTIVE</span>
        </div>
        """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div style="text-align: right; padding: 0.5rem;">
        <span style="color: #64748b;">Session: </span>
        <span style="font-weight: 600; color: #667eea;">#{st.session_state.get('current_log_file', 'N/A')}</span>
    </div>
    """, unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)


# ================= LIVE STREAM EXECUTION =================
if st.session_state.live_running and st.session_state.live_generator:
    try:
        event = next(st.session_state.live_generator)
        
        # Use severity directly from the event
        severity = event["severity"]

        # Get the full feature template with all columns
        from common.feature_template import base_feature_vector
        full_features = base_feature_vector()
        
        # Start with all feature template columns set to 0
        complete_features = {feature: 0 for feature in full_features.keys()}
        
        # Update with actual features from the event (if they exist)
        if "features" in event and event["features"]:
            complete_features.update(event["features"])
        
        # Create row_data with ALL features from complete_features
        row_data = {
            "packet": event["row"],
            **complete_features,  # ✅ CORRECT: Using complete_features with ALL columns
            "attack_name": event["attack_name"],
            "attack_class": event["attack_class"],
            "severity": severity,
            "confidence": event["confidence"]
        }

        # Store in session state
        st.session_state.live_packets_df.loc[len(st.session_state.live_packets_df)] = row_data
        
        # Add to chart data with numeric severity for plotting
        st.session_state.chart_data.loc[len(st.session_state.chart_data)] = {
            "packet": event["row"],
            "severity": SEVERITY_MAP[severity],
            "attack_class": event["attack_class"],
            "confidence": event["confidence"]
        }

        # Save to file
        save_log(st.session_state.current_log_file, row_data)

        # ===== DISPLAY CHART HERE DURING LIVE STREAM =====# ===== DISPLAY CHART HERE DURING LIVE STREAM =====
        if not st.session_state.chart_data.empty:
            st.markdown("## Live Threat Severity Timeline")
            
            # Create Plotly chart
            fig = go.Figure()
            
            # FIX: Use sequential packet numbers for display (1,2,3...) instead of stored packet numbers
            display_packets = list(range(1, len(st.session_state.chart_data) + 1))
            
            # Get data
            severity = st.session_state.chart_data['severity'].tolist()
            attack_classes = st.session_state.chart_data['attack_class'].tolist()
            confidence = st.session_state.chart_data['confidence'].tolist()
            
            # Define colors for ALL 5 severity levels
            severity_colors = {
                1: '#808080',  # Informational - Gray
                2: '#00FF00',  # Low - Green
                3: '#FFA500',  # Medium - Orange
                4: '#FF0000',  # High - Red
                5: '#8B0000'   # Critical - Dark Red
            }
            
            # Define names for ALL 5 severity levels
            severity_names = {
                1: 'Info',
                2: 'Low',
                3: 'Medium',
                4: 'High',
                5: 'Critical'
            }
            
            # Map severity values to colors
            colors = [severity_colors.get(s, '#808080') for s in severity]
            
            # Add main trace for data points using display_packets
            fig.add_trace(go.Scatter(
                x=display_packets,  # USE SEQUENTIAL NUMBERS HERE
                y=severity,
                mode='lines+markers',
                line=dict(color='#667eea', width=3),
                marker=dict(
                    size=12,
                    color=colors,
                    line=dict(color='white', width=2)
                ),
                text=[f"{attack_classes[i]}<br>Confidence: {confidence[i]*100:.1f}%" for i in range(len(display_packets))],
                hovertemplate='<b>Packet %{x}</b><br>' +
                            'Severity: %{customdata[0]}<br>' +
                            'Attack: %{text}<br>' +
                            '<extra></extra>',
                customdata=[[severity_names.get(s, 'Unknown')] for s in severity],
                showlegend=False
            ))
            
            # Add legend traces
            for level in [1, 2, 3, 4, 5]:
                fig.add_trace(go.Scatter(
                    x=[None],
                    y=[None],
                    mode='markers',
                    marker=dict(size=10, color=severity_colors[level]),
                    name=severity_names[level],
                    showlegend=True
                ))
            
            # Add LIVE indicator
            fig.add_annotation(
                x=0.98,
                y=0.98,
                xref="paper",
                yref="paper",
                text="🔴 LIVE",
                showarrow=False,
                font=dict(size=14, color="white"),
                bgcolor="#ef4444",
                bordercolor="#ef4444",
                borderwidth=1,
                borderpad=4,
                opacity=0.9
            )
            
            # Update layout
            fig.update_layout(
                height=450,
                margin=dict(l=40, r=40, t=40, b=40),
                paper_bgcolor='white',
                plot_bgcolor='#f8fafc',
                yaxis=dict(
                    tickmode='array',
                    tickvals=[1, 2, 3, 4, 5],
                    ticktext=['Info', 'Low', 'Medium', 'High', 'Critical'],
                    range=[0.5, 5.5],
                    gridcolor='#e2e8f0',
                    title='Severity'
                ),
                xaxis=dict(
                    title='Packet Number',
                    gridcolor='#e2e8f0',
                    tickmode='linear',
                    tick0=1,
                    dtick=1,
                    range=[0.5, len(display_packets) + 0.5]  # Set range based on actual count
                ),
                hoverlabel=dict(
                    bgcolor='white',
                    font_size=12,
                    font_family='Inter'
                ),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="center",
                    x=0.5,
                    bgcolor='rgba(255,255,255,0.8)',
                    bordercolor='#e2e8f0',
                    borderwidth=1,
                    font=dict(size=12)
                )
            )
            
            # Display the chart
            st.plotly_chart(fig, use_container_width=True)
            
            # Show mini stats with ACTUAL counts
            # Show mini stats with ACTUAL counts - USING STAT-CARD STYLING
            st.markdown("### Current Statistics")
            st.markdown('<div class="stats-grid">', unsafe_allow_html=True)

            col1, col2, col3, col4, col5, col6 = st.columns(6)

            with col1:
                st.markdown(f"""
                <div class="stat-card">
                    <div class="stat-value">{len(display_packets)}</div>
                    <div class="stat-label">Total Packets</div>
                    <div class="stat-change positive">↑ Live</div>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                info_count = severity.count(1)
                info_pct = (info_count / len(display_packets) * 100) if len(display_packets) > 0 else 0
                st.markdown(f"""
                <div class="stat-card">
                    <div class="stat-value">{info_count}</div>
                    <div class="stat-label">Info</div>
                    <div class="stat-change info">{info_pct:.1f}%</div>  <!-- Changed to class="stat-change info" -->
                </div>
                """, unsafe_allow_html=True)

            with col3:
                low_count = severity.count(2)
                low_pct = (low_count / len(display_packets) * 100) if len(display_packets) > 0 else 0
                st.markdown(f"""
                <div class="stat-card">
                    <div class="stat-value">{low_count}</div>
                    <div class="stat-label">Low</div>
                    <div class="stat-change low">{low_pct:.1f}%</div>  <!-- Changed to class="stat-change low" -->
                </div>
                """, unsafe_allow_html=True)

            with col4:
                medium_count = severity.count(3)
                medium_pct = (medium_count / len(display_packets) * 100) if len(display_packets) > 0 else 0
                st.markdown(f"""
                <div class="stat-card">
                    <div class="stat-value">{medium_count}</div>
                    <div class="stat-label">Medium</div>
                    <div class="stat-change medium">{medium_pct:.1f}%</div>  <!-- Changed to class="stat-change medium" -->
                </div>
                """, unsafe_allow_html=True)

            with col5:
                high_count = severity.count(4)
                high_pct = (high_count / len(display_packets) * 100) if len(display_packets) > 0 else 0
                st.markdown(f"""
                <div class="stat-card">
                    <div class="stat-value">{high_count}</div>
                    <div class="stat-label">High</div>
                    <div class="stat-change high">{high_pct:.1f}%</div>  <!-- Changed to class="stat-change high" -->
                </div>
                """, unsafe_allow_html=True)

            with col6:
                critical_count = severity.count(5)
                critical_pct = (critical_count / len(display_packets) * 100) if len(display_packets) > 0 else 0
                st.markdown(f"""
                <div class="stat-card">
                    <div class="stat-value">{critical_count}</div>
                    <div class="stat-label">Critical</div>
                    <div class="stat-change critical">{critical_pct:.1f}%</div>  <!-- Changed to class="stat-change critical" -->
                </div>
                """, unsafe_allow_html=True)

        # THESE MUST BE HERE - AFTER THE if BLOCK but INSIDE the try
        time.sleep(1)
        st.rerun()

    except StopIteration:
        st.session_state.live_running = False
        st.session_state.live_generator = None

# ===== CHART FOR AFTER STREAM STOPS =====
elif not st.session_state.live_running and not st.session_state.chart_data.empty:
    st.markdown("## Threat Severity Timeline")
    
    # Create Plotly chart
    fig = go.Figure()
    
    # FIX: Use sequential packet numbers for display
    display_packets = list(range(1, len(st.session_state.chart_data) + 1))
    
    severity = st.session_state.chart_data['severity'].tolist()
    attack_classes = st.session_state.chart_data['attack_class'].tolist()
    confidence = st.session_state.chart_data['confidence'].tolist()
    
    # Define colors
    severity_colors = {
        1: '#64748b',  # Informational - Gray
        2: '#22c55e',  # Low - Green
        3: '#f59e0b',  # Medium - Orange
        4: '#ef4444',  # High - Red
        5: '#7f1d1d'   # Critical - Dark Red
    }
    
    # Map severity values to colors
    colors = [severity_colors.get(s, '#64748b') for s in severity]
    
    # Add main trace
    fig.add_trace(go.Scatter(
        x=display_packets,  # USE SEQUENTIAL NUMBERS HERE
        y=severity,
        mode='lines+markers',
        line=dict(color='#667eea', width=3),
        marker=dict(
            size=12,
            color=colors,
            line=dict(color='white', width=2)
        ),
        text=attack_classes,
        hovertemplate='<b>Packet %{x}</b><br>' +
                     'Severity: %{y}<br>' +
                     'Attack: %{text}<br>' +
                     'Confidence: %{customdata:.1%}<extra></extra>',
        customdata=[[c] for c in confidence],
        showlegend=False
    ))
    
    # Add legend traces
    legend_names = {
        1: 'Informational',
        2: 'Low',
        3: 'Medium',
        4: 'High',
        5: 'Critical'
    }
    
    for level, color in severity_colors.items():
        fig.add_trace(go.Scatter(
            x=[None],
            y=[None],
            mode='markers',
            marker=dict(size=10, color=color),
            name=legend_names[level],
            showlegend=True
        ))
    
    fig.update_layout(
        height=450,
        margin=dict(l=40, r=40, t=40, b=40),
        paper_bgcolor='white',
        plot_bgcolor='#f8fafc',
        yaxis=dict(
            tickmode='array',
            tickvals=[1, 2, 3, 4, 5],
            ticktext=['Info', 'Low', 'Medium', 'High', 'Critical'],
            range=[0.5, 5.5],
            gridcolor='#e2e8f0',
            title='Severity'
        ),
        xaxis=dict(
            title='Packet Number',
            gridcolor='#e2e8f0',
            tickmode='linear',
            tick0=1,
            dtick=1,
            range=[0.5, len(display_packets) + 0.5]  # Set range based on actual count
        ),
        hoverlabel=dict(
            bgcolor='white',
            font_size=12,
            font_family='Inter'
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="center",
            x=0.5,
            bgcolor='rgba(255,255,255,0.8)',
            bordercolor='#e2e8f0',
            borderwidth=1
        )
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Show mini stats with ACTUAL counts
    # Show mini stats with ACTUAL counts
    st.markdown("### Final Statistics")
    st.markdown('<div class="stats-grid">', unsafe_allow_html=True)

    total_packets = len(display_packets)

    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{total_packets}</div>
            <div class="stat-label">Total Packets</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        info_count = severity.count(1)
        info_pct = (info_count / total_packets * 100) if total_packets > 0 else 0
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{info_count}</div>
            <div class="stat-label">Info</div>
            <div class="stat-change info">{info_pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        low_count = severity.count(2)
        low_pct = (low_count / total_packets * 100) if total_packets > 0 else 0
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{low_count}</div>
            <div class="stat-label">Low</div>
            <div class="stat-change low">{low_pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        medium_count = severity.count(3)
        medium_pct = (medium_count / total_packets * 100) if total_packets > 0 else 0
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{medium_count}</div>
            <div class="stat-label">Medium</div>
            <div class="stat-change medium">{medium_pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        high_count = severity.count(4)
        high_pct = (high_count / total_packets * 100) if total_packets > 0 else 0
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{high_count}</div>
            <div class="stat-label">High</div>
            <div class="stat-change high">{high_pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)

    with col6:
        critical_count = severity.count(5)
        critical_pct = (critical_count / total_packets * 100) if total_packets > 0 else 0
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{critical_count}</div>
            <div class="stat-label">Critical</div>
            <div class="stat-change critical">{critical_pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

    # Add verification
    if display_packets:
        st.caption(f"📊 Packet numbers shown: 1-{max(display_packets)} ({len(display_packets)} total packets)")


# Show placeholder when no data and live
elif st.session_state.live_running and st.session_state.chart_data.empty:
    st.markdown("## Live Threat Severity Timeline")
    st.info("Waiting for packets... Chart will appear as data arrives", icon="🔄")
    st.markdown("""
    <div style="height: 400px; background: #f8fafc; border-radius: 10px; display: flex; align-items: center; justify-content: center; border: 2px dashed #e2e8f0;">
        <p style="color: #94a3b8;">Chart will appear here</p>
    </div>
    """, unsafe_allow_html=True)


# ================= LIVE PACKETS TABLE =================
if st.session_state.live_running and not st.session_state.live_packets_df.empty:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("## Recent Packets")
    
    # Show last 10 packets
    recent_df = st.session_state.live_packets_df.tail(10).copy()
    recent_df['protocol'] = recent_df['protocol_type'].map(lambda x: PROTOCOL_MAP.get(x, 'OTHER'))
    
    # Add emoji for severity
    def severity_emoji(sev):
        emojis = {
            'Informational': '🔘',
            'Low': '🟢',
            'Medium': '🟠',
            'High': '🔴',
            'Critical': '⭕'
        }
        return f"{emojis.get(sev, '⚪')} {sev}"
    
    recent_df['severity_display'] = recent_df['severity'].apply(severity_emoji)
    
    display_df = recent_df[['packet', 'attack_name', 'attack_class', 'severity_display', 'confidence', 'protocol']].rename(
        columns={
            'packet': 'Packet #',
            'attack_name': 'Attack',
            'attack_class': 'Class',
            'severity_display': 'Severity',
            'confidence': 'Confidence',
            'protocol': 'Protocol'
        }
    )
    display_df['Confidence'] = display_df['Confidence'].apply(lambda x: f"{x*100:.1f}%")
    
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ================= TABS SECTION - ONLY WHEN STOPPED =================
if not st.session_state.live_running and not st.session_state.live_packets_df.empty:
    st.markdown("## Analysis Dashboard")
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Packet Analysis",
        "Attack Search", 
        "Severity Distribution",
        "Full Results",
        "Statistics"
    ])

    live_df = st.session_state.live_packets_df
    

    # ---------------- PACKET ANALYSIS ----------------# ---------------- PACKET ANALYSIS - FIXED ALIGNMENT ----------------
    with tab1:
        st.markdown("### Analyze Individual Packets")
        
        # Create two equal columns
        col_left, col_right = st.columns(2, gap="large")
        
        with col_left:
            packet_num = st.number_input(
                "Select Packet Number",
                min_value=1,
                max_value=len(live_df),
                value=1,
                step=1,
                key="packet_selector"
            )
            
            # Get packet data
            packet_data = live_df.iloc[packet_num - 1]
            severity = packet_data.get('severity', 'Informational')  # Use stored severity
            
            # Severity color mapping for ALL 5 levels
            color_map = {
                "Informational": "#64748b",  # Gray
                "Low": "#22c55e",            # Green
                "Medium": "#f59e0b",         # Orange
                "High": "#ef4444",            # Red
                "Critical": "#7f1d1d"         # Dark Red
            }
            sev_color = color_map.get(severity, "#64748b")
            
            # Packet summary card - with severity color hints
            st.markdown(f"""
            <div style="background: #f9f9f9; border-radius: 8px; padding: 1.2rem; margin-top: 1rem; border-left: 4px solid {sev_color};">
                <h4 style="margin-bottom: 1.2rem; font-size: 1rem; font-weight: 500; color: {sev_color};">Packet Summary</h4>
                <div style="margin-bottom: 1rem;">
                    <div style="color: #666; font-size: 0.8rem;">Attack Type</div>
                    <div style="font-size: 1.3rem; font-weight: 600;">{packet_data['attack_name'].capitalize()}</div>
                </div>
                <div style="margin-bottom: 1rem;">
                    <div style="color: #666; font-size: 0.8rem;">Attack Class</div>
                    <div style="font-size: 1.1rem;">{packet_data['attack_class']}</div>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="color: #666; font-size: 0.8rem;">Severity</div>
                        <div style="font-size: 1.1rem; font-weight: 600; color: {sev_color};">{severity}</div>
                    </div>
                    <div>
                        <div style="color: #666; font-size: 0.8rem;">Confidence</div>
                        <div style="font-size: 1.8rem; font-weight: 600; color: {sev_color};">{packet_data['confidence']*100:.1f}%</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col_right:
            # Detection Confidence Gauge
            st.markdown("### Detection Confidence")
            
            # Create gauge chart with 5 severity levels
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=packet_data['confidence']*100,
                number={'font': {'size': 36, 'color': sev_color}},
                title={'text': f"Confidence Level - {severity}", 'font': {'size': 13, 'color': sev_color}},
                domain={'x': [0, 1], 'y': [0, 1]},
                gauge={
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#ccc", 
                            'tickmode': 'array', 'tickvals': [0, 20, 40, 60, 80, 100]},
                    'bar': {'color': sev_color, 'thickness': 0.3},
                    'bgcolor': 'white',
                    'borderwidth': 0,
                    'steps': [
                        {'range': [0, 20], 'color': '#e8f5e8'},   # Very Light Green (Info/Low range)
                        {'range': [20, 40], 'color': '#d4edda'},  # Light Green (Low range)
                        {'range': [40, 60], 'color': '#fff3e0'},  # Light Orange (Medium range)
                        {'range': [60, 80], 'color': '#ffe8e8'},  # Light Red (High range)
                        {'range': [80, 100], 'color': '#ffd7d7'}   # Darker Light Red (Critical range)
                    ],
                    'threshold': {
                        'line': {'color': sev_color, 'width': 4},
                        'thickness': 0.75,
                        'value': packet_data['confidence']*100
                    }
                }
            ))
            
            # Add severity level markers
            fig.add_annotation(
                x=0.05, y=0.15,
                text="Info/Low",
                showarrow=False,
                font=dict(size=9, color="#64748b"),
                xref="paper", yref="paper"
            )
            fig.add_annotation(
                x=0.25, y=0.15,
                text="Low",
                showarrow=False,
                font=dict(size=9, color="#22c55e"),
                xref="paper", yref="paper"
            )
            fig.add_annotation(
                x=0.45, y=0.15,
                text="Medium",
                showarrow=False,
                font=dict(size=9, color="#f59e0b"),
                xref="paper", yref="paper"
            )
            fig.add_annotation(
                x=0.65, y=0.15,
                text="High",
                showarrow=False,
                font=dict(size=9, color="#ef4444"),
                xref="paper", yref="paper"
            )
            fig.add_annotation(
                x=0.85, y=0.15,
                text="Critical",
                showarrow=False,
                font=dict(size=9, color="#7f1d1d"),
                xref="paper", yref="paper"
            )
            
            fig.update_layout(
                height=320,
                margin=dict(l=20, r=20, t=50, b=30),
                paper_bgcolor='white'
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Protocol info with severity color
            protocol = PROTOCOL_MAP.get(packet_data.get('protocol_type', 0), 'Unknown')
            st.markdown(f"""
            <div style="background: #f5f5f5; border-radius: 6px; padding: 0.6rem; text-align: center; font-size: 0.9rem; border-left: 4px solid {sev_color};">
                <span style="color: #666;">Protocol:</span> <span style="font-weight: 500; color: {sev_color};">{protocol}</span>
            </div>
            """, unsafe_allow_html=True)

    # ---------------- ATTACK SEARCH ----------------
    with tab2:
        st.markdown("### Search Attacks")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            search_query = st.text_input("Enter attack name or class", placeholder="e.g., neptune, dos, normal...")
        
        with col2:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["Informational", "Low", "Medium", "High", "Critical"],  # FIX: Added all severity levels
                default=["High", "Medium", "Low"]
            )
        
        if search_query:
            # Search in both attack_name and attack_class
            mask = (
                live_df['attack_name'].str.contains(search_query, case=False, na=False) |
                live_df['attack_class'].str.contains(search_query, case=False, na=False)
            )
            
            # Apply severity filter
            if severity_filter:
                severity_mask = live_df['severity'].isin(severity_filter)
                mask = mask & severity_mask
            
            results = live_df[mask].copy()
            
            if not results.empty:
                st.markdown(f"### Found {len(results)} Matching Results")
                
                for idx, row in results.iterrows():
                    # FIX: Use stored severity from dataframe, don't recalculate
                    severity = row['severity']  # CORRECT - use stored value
                    
                    # FIX: Use proper color mapping for all severity levels
                    color_map = {
                        "Informational": "#64748b",
                        "Low": "#22c55e",
                        "Medium": "#f59e0b",
                        "High": "#ef4444",
                        "Critical": "#7f1d1d"
                    }
                    sev_color = color_map.get(severity, "#64748b")
                    
                    st.markdown(f"""
                    <div class="alert-card {severity.lower()}">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div>
                                <div class="alert-title">{row['attack_name'].capitalize()}</div>
                                <div class="alert-meta">
                                    <span>Class: {row['attack_class']}</span>
                                    <span>Packet #{int(row['packet'])}</span>
                                    <span>Confidence: {row['confidence']*100:.1f}%</span>
                                </div>
                            </div>
                            <div style="background: {sev_color}; color: white; padding: 0.25rem 1rem; border-radius: 50px; font-size: 0.9rem;">
                                {severity}
                            </div>
                        </div>
                        <div class="alert-progress">
                            <div class="alert-progress-fill" style="width: {row['confidence']*100}%; background: {sev_color};"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No matching attacks found")
                
    # ---------------- SEVERITY DISTRIBUTION ----------------
    with tab3:
        st.markdown("### Severity Analysis")
        
        # Create two columns for the pie chart and attack distribution
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Severity Distribution")
            
            # Get severity counts
            severity_counts = live_df['severity'].value_counts().reset_index()
            severity_counts.columns = ['Severity', 'Count']
            
            # FORCE all 5 severity levels to appear even if count is 0
            all_severities = ['Informational', 'Low', 'Medium', 'High', 'Critical']
            
            # Create a complete dataframe with all severity levels
            complete_data = []
            for sev in all_severities:
                count = severity_counts[severity_counts['Severity'] == sev]['Count'].values
                count_value = count[0] if len(count) > 0 else 0
                complete_data.append({'Severity': sev, 'Count': count_value})
            
            complete_df = pd.DataFrame(complete_data)
            
            # Define colors for ALL 5 levels
            colors = {
                'Informational': '#64748b',  # Gray
                'Low': '#22c55e',            # Green
                'Medium': '#f59e0b',          # Orange
                'High': '#ef4444',             # Red
                'Critical': '#7f1d1d'          # Dark Red
            }
            
            # Create pie chart with ALL segments
            fig_pie = go.Figure(data=[go.Pie(
                labels=complete_df['Severity'],
                values=complete_df['Count'],
                marker=dict(
                    colors=[colors[sev] for sev in complete_df['Severity']],
                    line=dict(color='white', width=2)
                ),
                textinfo='label+percent',
                textposition='inside',
                hole=0.4,
                sort=False,  # Don't sort, keep our order
                direction='clockwise',
                rotation=90
            )])
            
            fig_pie.update_layout(
                title="Threat Severity Distribution (All 5 Levels)",
                height=400,
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="center",
                    x=0.5
                ),
                annotations=[
                    dict(
                        text=f'Total: {len(live_df)}',
                        x=0.5, y=0.5,
                        font=dict(size=16, color='#1e293b'),
                        showarrow=False
                    )
                ]
            )
            
            st.plotly_chart(fig_pie, use_container_width=True)

        with col2:
            st.markdown("### Top Attack Classes by Severity")
            
            # Get top attack classes
            attack_counts = live_df['attack_class'].value_counts().head(10).reset_index()
            attack_counts.columns = ['Attack Class', 'Count']
            
            # Get severity for each attack class (use the most common severity)
            attack_severities = []
            for attack in attack_counts['Attack Class']:
                # Get the most frequent severity for this attack class
                sev_counts = live_df[live_df['attack_class'] == attack]['severity'].value_counts()
                if len(sev_counts) > 0:
                    most_common_sev = sev_counts.index[0]
                    attack_severities.append(most_common_sev)
                else:
                    attack_severities.append('Informational')
            
            # Map severities to colors for ALL 5 levels
            severity_to_color = {
                'Informational': '#64748b',
                'Low': '#22c55e',
                'Medium': '#f59e0b',
                'High': '#ef4444',
                'Critical': '#7f1d1d'
            }
            
            bar_colors = [severity_to_color.get(sev, '#64748b') for sev in attack_severities]
            
            fig_attack = go.Figure(data=[
                go.Bar(
                    x=attack_counts['Count'],
                    y=attack_counts['Attack Class'],
                    orientation='h',
                    marker=dict(
                        color=bar_colors,
                        line=dict(color='white', width=1)
                    ),
                    text=attack_counts['Count'],
                    textposition='outside',
                    hovertemplate='<b>%{y}</b><br>' +
                                'Count: %{x}<br>' +
                                'Severity: %{customdata}<extra></extra>',
                    customdata=attack_severities
                )
            ])
            
            fig_attack.update_layout(
                title="Top 10 Attack Classes (Colored by Severity)",
                xaxis_title="Count",
                yaxis_title="Attack Class",
                height=400,
                margin=dict(l=0, r=0, t=50, b=0),
                xaxis=dict(gridcolor='#e2e8f0'),
                yaxis=dict(gridcolor='#e2e8f0')
            )
            
            st.plotly_chart(fig_attack, use_container_width=True)
        
        # ===== SEVERITY TIMELINE =====
        st.markdown("### Severity Timeline")
        
        if len(live_df) > 1:
            severity_over_time = live_df.copy()
            severity_over_time['severity_num'] = severity_over_time['severity'].map(SEVERITY_MAP)
            
            # Create color mapping for each point
            colors = []
            for sev in severity_over_time['severity']:
                if sev == 'Informational':
                    colors.append('#64748b')
                elif sev == 'Low':
                    colors.append('#22c55e')
                elif sev == 'Medium':
                    colors.append('#f59e0b')
                elif sev == 'High':
                    colors.append('#ef4444')
                elif sev == 'Critical':
                    colors.append('#7f1d1d')
                else:
                    colors.append('#64748b')
            
            fig_timeline = go.Figure()
            
            fig_timeline.add_trace(go.Scatter(
                x=severity_over_time['packet'],
                y=severity_over_time['severity_num'],
                mode='lines+markers',
                line=dict(color='#667eea', width=2, dash='dot'),
                marker=dict(
                    size=12,
                    color=colors,
                    line=dict(color='white', width=2)
                ),
                text=severity_over_time.apply(
                    lambda row: f"Class: {row['attack_class']}<br>Severity: {row['severity']}<br>Confidence: {row['confidence']*100:.1f}%", 
                    axis=1
                ),
                hovertemplate='Packet %{x}<br>%{text}<extra></extra>',
                name='Severity'
            ))
            
            fig_timeline.update_layout(
                title="Severity Changes Over Time",
                xaxis_title="Packet Number",
                yaxis=dict(
                    tickmode='array',
                    tickvals=[1, 2, 3, 4, 5],
                    ticktext=['Info', 'Low', 'Medium', 'High', 'Critical'],
                    range=[0.5, 5.5]
                ),
                height=400,
                hovermode='x unified',
                showlegend=False
            )
            
            st.plotly_chart(fig_timeline, use_container_width=True)
            
            # Add some summary stats below the timeline
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                severity_changes = severity_over_time['severity_num'].diff().fillna(0).abs().sum()
                st.metric("Severity Changes", f"{severity_changes:.0f}")
            with col2:
                most_common = severity_over_time['severity'].mode()[0] if not severity_over_time.empty else "N/A"
                st.metric("Most Common", most_common)
            with col3:
                avg_severity = severity_over_time['severity_num'].mean()
                st.metric("Avg Severity", f"{avg_severity:.1f}")
            with col4:
                max_severity = severity_over_time['severity'].max()
                st.metric("Max Severity", max_severity)
        
        else:
            st.info("Not enough data points to display timeline (need at least 2 packets)")
    

        # ---------------- FULL RESULTS ----------------
    with tab4:
        st.markdown("### 📋 Complete Detection Results")
        
        # Filters row
        col1, col2, col3 = st.columns(3)
        
        with col1:
            severity_options = ["All", "Informational", "Low", "Medium", "High", "Critical"]
            filter_severity = st.selectbox(
                "Filter by Severity",
                options=severity_options,
                index=0,
                key="severity_filter"
            )
        
        with col2:
            filter_class = st.selectbox(
                "Filter by Attack Class",
                options=["All"] + sorted(live_df['attack_class'].unique().tolist()),
                key="class_filter"
            )
        
        with col3:
            min_confidence = st.slider(
                "Minimum Confidence", 
                0.0, 1.0, 0.0, 0.05,
                key="conf_filter"
            )
        
        # Apply filters
        filtered_df = live_df.copy()
        if filter_severity != "All":
            filtered_df = filtered_df[filtered_df['severity'] == filter_severity]
        if filter_class != "All":
            filtered_df = filtered_df[filtered_df['attack_class'] == filter_class]
        if min_confidence > 0:
            filtered_df = filtered_df[filtered_df['confidence'] >= min_confidence]
        
        st.info(f"📊 Showing **{len(filtered_df)}** of **{len(live_df)}** total packets")
        
        # ===== FULL FEATURE TABLE (NO DROPDOWN) =====
        st.markdown("### 📊 Full Feature Table")
        
        # Define all features
        all_features = [
            'packet', 'attack_name', 'attack_class', 'severity', 'confidence',
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
            'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root',
            'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        
        # Create display dataframe with all features
        display_df = filtered_df[[col for col in all_features if col in filtered_df.columns]].copy()
        
        # Format the dataframe for better display
        formatted_df = display_df.copy()
        
        # Format confidence
        if 'confidence' in formatted_df.columns:
            formatted_df['confidence'] = formatted_df['confidence'].apply(lambda x: f"{x*100:.1f}%")
        
        # Format protocol
        if 'protocol_type' in formatted_df.columns:
            formatted_df['protocol_type'] = formatted_df['protocol_type'].map(lambda x: PROTOCOL_MAP.get(x, 'OTHER'))
        
        # Format severity with emoji
        if 'severity' in formatted_df.columns:
            severity_emojis = {
                'Informational': 'ℹ️',
                'Low': '🟢',
                'Medium': '🟠',
                'High': '🔴',
                'Critical': '💀'
            }
            formatted_df['severity'] = formatted_df['severity'].apply(
                lambda x: f"{severity_emojis.get(x, '⚪')} {x}"
            )
        
        # Format float columns (except confidence which is already formatted)
        for col in formatted_df.select_dtypes(include=['float64']).columns:
            if col != 'confidence':
                formatted_df[col] = formatted_df[col].apply(
                    lambda x: f"{x:.4f}" if x < 0.01 else f"{x:.2f}"
                )
        
        # Display as Excel-like table
        st.markdown('<div class="excel-table-container">', unsafe_allow_html=True)
        st.dataframe(
            formatted_df,
            use_container_width=True,
            hide_index=True,
            height=500
        )
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Show row and column count
        st.caption(f"📋 Showing **{len(formatted_df)}** rows × **{len(formatted_df.columns)}** columns")
        
        # Download button
        csv = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Full Results CSV",
            data=csv,
            file_name=f"detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    # ---------------- STATISTICS ----------------
    with tab5:
        st.markdown("### Advanced Statistics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Protocol distribution
            protocol_counts = live_df['protocol_type'].value_counts().reset_index()
            protocol_counts.columns = ['Protocol', 'Count']
            protocol_counts['Protocol'] = protocol_counts['Protocol'].map(lambda x: PROTOCOL_MAP.get(x, 'OTHER'))
            
            fig = go.Figure(data=[
                go.Bar(
                    x=protocol_counts['Protocol'],
                    y=protocol_counts['Count'],
                    marker=dict(color=['#667eea', '#764ba2', '#f59e0b']),
                    text=protocol_counts['Count'],
                    textposition='outside'
                )
            ])
            
            fig.update_layout(
                title="Protocol Distribution",
                xaxis_title="Protocol",
                yaxis_title="Count",
                height=350
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Top attacks
            top_attacks = live_df['attack_name'].value_counts().head(10)
            
            fig = go.Figure(data=[
                go.Bar(
                    x=top_attacks.values,
                    y=top_attacks.index,
                    orientation='h',
                    marker=dict(
                        color=['#ef4444' if i < 3 else '#f59e0b' if i < 7 else '#22c55e' 
                               for i in range(len(top_attacks))],
                        line=dict(color='rgba(0,0,0,0.1)', width=1)
                    )
                )
            ])
            
            fig.update_layout(
                title="Top 10 Detected Attacks",
                xaxis_title="Count",
                yaxis_title="Attack Type",
                height=350
            )
            
            st.plotly_chart(fig, use_container_width=True)

        # Statistical summary
        st.markdown("### Severity Breakdown")

        # Create 5 columns for all severity levels
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            info_count = len(live_df[live_df['severity'] == 'Informational'])
            info_pct = (info_count / len(live_df) * 100) if len(live_df) > 0 else 0
            st.metric(
                "📊 Informational",
                info_count,
                delta=f"{info_pct:.1f}%",
                delta_color="off"
            )

        with col2:
            low_count = len(live_df[live_df['severity'] == 'Low'])
            low_pct = (low_count / len(live_df) * 100) if len(live_df) > 0 else 0
            st.metric(
                "🟢 Low",
                low_count,
                delta=f"{low_pct:.1f}%",
                delta_color="normal"
            )

        with col3:
            medium_count = len(live_df[live_df['severity'] == 'Medium'])
            medium_pct = (medium_count / len(live_df) * 100) if len(live_df) > 0 else 0
            st.metric(
                "🟠 Medium",
                medium_count,
                delta=f"{medium_pct:.1f}%",
                delta_color="normal"
            )

        with col4:
            high_count = len(live_df[live_df['severity'] == 'High'])
            high_pct = (high_count / len(live_df) * 100) if len(live_df) > 0 else 0
            st.metric(
                "🔴 High",
                high_count,
                delta=f"{high_pct:.1f}%",
                delta_color="inverse"
            )

        with col5:
            critical_count = len(live_df[live_df['severity'] == 'Critical'])
            critical_pct = (critical_count / len(live_df) * 100) if len(live_df) > 0 else 0
            st.metric(
                "💀 Critical",
                critical_count,
                delta=f"{critical_pct:.1f}%",
                delta_color="inverse"
            )

# ================= EMPTY STATE =================
if not st.session_state.live_running and st.session_state.live_packets_df.empty:
    st.markdown("""
    <div style="text-align: center; padding: 5rem 2rem; background: white; border-radius: 30px; margin: 2rem 0;">
        <div style="font-size: 5rem; margin-bottom: 1rem;"></div>
        <h3 style="color: #1e293b; margin-bottom: 0.5rem;">Ready to Monitor Network Traffic</h3>
        <p style="color: #64748b; margin-bottom: 2rem;">Click 'Start Live Detection' to begin analyzing network packets in real-time</p>
        <div style="display: flex; gap: 1rem; justify-content: center;">
            <div style="background: #f1f5f9; padding: 1rem 2rem; border-radius: 15px;">
                <span style="color: #667eea; font-weight: 600;">Real-time Analysis</span>
            </div>
            <div style="background: #f1f5f9; padding: 1rem 2rem; border-radius: 15px;">
                <span style="color: #667eea; font-weight: 600;">Threat Detection</span>
            </div>
            <div style="background: #f1f5f9; padding: 1rem 2rem; border-radius: 15px;">
                <span style="color: #667eea; font-weight: 600;">Live Dashboard</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ================= FOOTER =================
st.markdown("""
<div class="footer">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <span style="font-weight: 700;">🛡️ Intrusion Detection System</span> • Real-time Network Security Monitoring
        </div>
        <div>
            <span style="margin: 0 1rem;">Version 2.0</span>
            <span style="margin: 0 1rem;">•</span>
            <span>© 2026 All Rights Reserved</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)
