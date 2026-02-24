import streamlit as st
import pandas as pd
import os
from datetime import datetime

from common.session import require_login, require_role
from common.sidebar import render_user_sidebar
from common.log_utils import list_sessions
from common.detection_utlis import detect_severity


# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="IDS Security Console", 
    layout="wide",
    page_icon="🛡️"
)

# ================= AUTH =================
require_login()
require_role("user")
render_user_sidebar()

# ================= SESSION STATE =================
if "selected_session_file" not in st.session_state:
    st.session_state.selected_session_file = None

# ================= INFO =================
if (
    "live_packets_df" not in st.session_state
    or st.session_state.live_packets_df.empty
):
    st.info("ℹ️ Live stream not started. Showing previous logs if available.")

# ================= LOAD DATA =================
if "live_packets_df" in st.session_state and not st.session_state.live_packets_df.empty:
    df = st.session_state.live_packets_df.copy()
else:
    df = pd.DataFrame(columns=["attack_name", "attack_class", "severity"])

# ================= METRICS =================
total = len(df)
if "attack_class" in df.columns:
    attack_df = df[df["attack_class"] != "Normal"]
else:
    attack_df = pd.DataFrame()

attacks = len(attack_df)

# Five severity levels
informational = (df.get("severity") == "Informational").sum()
low = (df.get("severity") == "Low").sum()
medium = (df.get("severity") == "Medium").sum()
high = (df.get("severity") == "High").sum()
critical = (df.get("severity") == "Critical").sum()

ratio = round((attacks / total) * 100, 2) if total else 0

user_email = st.session_state.get("email", "user")
user_name = user_email.split("@")[0].capitalize() if "@" in user_email else user_email.capitalize()

# ================= CUSTOM CSS =================
st.markdown("""
<style>
/* Import Google Font */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

.stApp {
    font-family: 'Inter', sans-serif;
    background: #f8fafc;
}

/* Header - matching other pages */
.glass-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1.2rem 2rem;
    border-radius: 20px;
    margin-bottom: 2rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: white;
}

.header-title {
    font-size: 1.5rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.header-user {
    background: rgba(255,255,255,0.2);
    padding: 0.5rem 1.2rem;
    border-radius: 50px;
    font-size: 0.9rem;
    font-weight: 500;
}

/* Stats Cards - Updated for 5 columns */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1rem;
    margin: 1.5rem 0;
}

.stat-card {
    background: white;
    padding: 1rem;
    border-radius: 16px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    border: 1px solid #eef2f6;
    border-left: 4px solid;
}

.stat-card.info { border-left-color: #64748b; }
.stat-card.low { border-left-color: #22c55e; }
.stat-card.medium { border-left-color: #f59e0b; }
.stat-card.high { border-left-color: #ef4444; }
.stat-card.critical { border-left-color: #7f1d1d; }

.stat-label {
    font-size: 0.75rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.stat-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: #1e293b;
    margin: 0.2rem 0;
}

.stat-desc {
    font-size: 0.65rem;
    color: #94a3b8;
}

/* Panels */
.panel-container {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin: 1.5rem 0;
}

.threat-panel, .risk-panel {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    border: 1px solid #eef2f6;
    height: 340px;
}

.panel-title {
    font-size: 1rem;
    font-weight: 600;
    color: #334155;
    margin-bottom: 1.2rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.panel-title span {
    background: #f1f5f9;
    padding: 0.2rem 0.8rem;
    border-radius: 50px;
    font-size: 0.7rem;
    color: #64748b;
}

/* Threat Bars - Updated for 5 severities */
.threat-row {
    margin-bottom: 0.8rem;
}

.threat-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.8rem;
    color: #475569;
    margin-bottom: 0.2rem;
}

.threat-bar {
    height: 8px;
    background: #f1f5f9;
    border-radius: 10px;
    overflow: hidden;
}

.threat-fill {
    height: 100%;
    border-radius: 10px;
}

.threat-fill.critical { background: #7f1d1d; }
.threat-fill.high { background: #ef4444; }
.threat-fill.medium { background: #f59e0b; }
.threat-fill.low { background: #22c55e; }
.threat-fill.info { background: #64748b; }

/* Risk Panel */
.risk-panel {
    background: linear-gradient(135deg, #1e293b, #0f172a);
    color: white;
}

.risk-badge {
    font-size: 0.8rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.risk-level {
    font-size: 2rem;
    font-weight: 700;
    margin: 0.8rem 0;
}

.risk-level.critical { color: #7f1d1d; }
.risk-level.high { color: #ef4444; }
.risk-level.medium { color: #f59e0b; }
.risk-level.low { color: #22c55e; }
.risk-level.info { color: #94a3b8; }

.risk-text {
    font-size: 0.9rem;
    color: #cbd5e1;
    margin-bottom: 1rem;
}

.risk-tags {
    display: flex;
    gap: 0.8rem;
    flex-wrap: wrap;
}

.risk-tag {
    background: rgba(255,255,255,0.1);
    padding: 0.4rem 1rem;
    border-radius: 50px;
    font-size: 0.75rem;
    color: #e2e8f0;
}

/* Session CTA - Updated for 5 severities */
.session-card {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    margin: 1.5rem 0;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    border: 1px solid #eef2f6;
    border-left: 4px solid;
}

.session-card.critical { border-left-color: #7f1d1d; }
.session-card.high { border-left-color: #ef4444; }
.session-card.medium { border-left-color: #f59e0b; }
.session-card.low { border-left-color: #22c55e; }
.session-card.info { border-left-color: #64748b; }

.session-header {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin-bottom: 0.5rem;
}

.session-icon {
    font-size: 1.5rem;
}

.session-title {
    font-size: 1.2rem;
    font-weight: 600;
    color: #1e293b;
}

.session-desc {
    font-size: 0.9rem;
    color: #64748b;
    margin-bottom: 1rem;
}

.session-stats {
    display: flex;
    gap: 1.5rem;
    font-size: 0.8rem;
    color: #475569;
}

/* Button */
.stButton > button {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
    color: white !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 0.8rem !important;
    font-weight: 600 !important;
    font-size: 0.95rem !important;
    transition: all 0.3s ease !important;
    width: 100%;
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(102,126,234,0.3) !important;
}

/* Info message */
.stAlert {
    background: #f8fafc !important;
    border: 1px solid #e2e8f0 !important;
    border-left: 4px solid #667eea !important;
    color: #1e293b !important;
    border-radius: 12px !important;
}

/* Section titles */
.section-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: #1e293b;
    margin: 1.5rem 0 1rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

/* Footer */
.footer {
    text-align: center;
    padding: 1.5rem;
    color: #94a3b8;
    font-size: 0.8rem;
    border-top: 1px solid #e2e8f0;
    margin-top: 2rem;
}

/* Responsive */
@media (max-width: 1200px) {
    .stats-grid {
        grid-template-columns: repeat(3, 1fr);
    }
    .panel-container {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 768px) {
    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}
</style>
""", unsafe_allow_html=True)

# ================= HEADER =================
st.markdown(f"""
<div class="glass-header">
    <div class="header-title">
        <span>🛡️</span> IDS Security Console
    </div>
    <div class="header-user">
        👤 {user_name} • {datetime.now().strftime('%I:%M %p')}
    </div>
</div>
""", unsafe_allow_html=True)

# ================= STATS CARDS - Updated for 5 severities =================

st.markdown('<div class="stats-grid">', unsafe_allow_html=True)
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(f"""
    <div class="stat-card info">
        <div class="stat-label">Traffic Analyzed</div>
        <div class="stat-value">{total:,}</div>
        <div class="stat-desc">total packets</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="stat-card low">
        <div class="stat-label">Informational</div>
        <div class="stat-value">{informational}</div>
        <div class="stat-desc">{((informational/total)*100 if total>0 else 0):.1f}% of traffic</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="stat-card medium">
        <div class="stat-label">Low Severity</div>
        <div class="stat-value">{low}</div>
        <div class="stat-desc">{((low/total)*100 if total>0 else 0):.1f}% of total</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="stat-card high">
        <div class="stat-label">Medium Severity</div>
        <div class="stat-value">{medium}</div>
        <div class="stat-desc">{((medium/total)*100 if total>0 else 0):.1f}% of total</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    st.markdown(f"""
    <div class="stat-card critical">
        <div class="stat-label">High + Critical</div>
        <div class="stat-value">{high + critical}</div>
        <div class="stat-desc">High: {high} | Critical: {critical}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)

# ================= DISTRIBUTION + RISK - Updated for 5 severities =================
st.markdown('<div class="section-title"><span></span> Threat Analysis</div>', unsafe_allow_html=True)

col_left, col_right = st.columns(2)

with col_left:
    total_events = informational + low + medium + high + critical or 1
    info_pct = (informational/total_events)*100
    low_pct = (low/total_events)*100
    medium_pct = (medium/total_events)*100
    high_pct = (high/total_events)*100
    critical_pct = (critical/total_events)*100
    
    st.markdown(f"""
    <div class="threat-panel">
        <div class="panel-title">
            <span></span> Severity Distribution
            <span>live</span>
        </div>
        <div class="threat-row">
            <div class="threat-label">
                <span>⚪ Informational</span>
                <span>{informational} ({info_pct:.1f}%)</span>
            </div>
            <div class="threat-bar"><div class="threat-fill info" style="width:{info_pct}%"></div></div>
        </div>
        <div class="threat-row">
            <div class="threat-label">
                <span>🟢 Low</span>
                <span>{low} ({low_pct:.1f}%)</span>
            </div>
            <div class="threat-bar"><div class="threat-fill low" style="width:{low_pct}%"></div></div>
        </div>
        <div class="threat-row">
            <div class="threat-label">
                <span>🟠 Medium</span>
                <span>{medium} ({medium_pct:.1f}%)</span>
            </div>
            <div class="threat-bar"><div class="threat-fill medium" style="width:{medium_pct}%"></div></div>
        </div>
        <div class="threat-row">
            <div class="threat-label">
                <span>🔴 High</span>
                <span>{high} ({high_pct:.1f}%)</span>
            </div>
            <div class="threat-bar"><div class="threat-fill high" style="width:{high_pct}%"></div></div>
        </div>
        <div class="threat-row">
            <div class="threat-label">
                <span>🔥 Critical</span>
                <span>{critical} ({critical_pct:.1f}%)</span>
            </div>
            <div class="threat-bar"><div class="threat-fill critical" style="width:{critical_pct}%"></div></div>
        </div>
        <div style="margin-top:0.8rem; padding-top:0.8rem; border-top:1px solid #eef2f6; font-size:0.8rem; color:#94a3b8;">
            Total Events: {informational + low + medium + high + critical}
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_right:
    if critical > 0:
        level, desc, risk_class = "CRITICAL RISK", "Critical intrusions detected - Immediate action required", "critical"
        icon = "🔥"
    elif high > 0:
        level, desc, risk_class = "HIGH RISK", "Severe threats detected", "high"
        icon = "🚨"
    elif medium > 0:
        level, desc, risk_class = "MODERATE RISK", "Suspicious activity detected", "medium"
        icon = "⚠️"
    elif low > 0:
        level, desc, risk_class = "LOW RISK", "Minor anomalies detected", "low"
        icon = "ℹ️"
    else:
        level, desc, risk_class = "INFORMATIONAL", "System is secure - No threats", "info"
        icon = "✅"

    st.markdown(f"""
    <div class="risk-panel">
        <div class="risk-badge">{icon} Current Status</div>
        <div class="risk-level {risk_class}">{level}</div>
        <div class="risk-text">{desc}</div>
        <div class="risk-tags">
            <span class="risk-tag">Critical: {critical}</span>
            <span class="risk-tag">High: {high}</span>
            <span class="risk-tag">Medium: {medium}</span>
            <span class="risk-tag">Low: {low}</span>
            <span class="risk-tag">Info: {informational}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ================= SESSION CARD - Updated for 5 severities =================
if critical > 0:
    card_class = "critical"
    icon = "🔥"
    title = "Critical Security Alert"
    desc = f"{critical} critical severity threats detected"
elif high > 0:
    card_class = "high"
    icon = "🚨"
    title = "High Severity Alert"
    desc = f"{high} high severity threats detected"
elif medium > 0:
    card_class = "medium"
    icon = "⚠️"
    title = "Suspicious Activity"
    desc = f"{medium} medium severity threats found"
elif low > 0:
    card_class = "low"
    icon = "ℹ️"
    title = "Low Severity Events"
    desc = f"{low} low severity events detected"
else:
    card_class = "info"
    icon = "✅"
    title = "All Clear"
    desc = f"{informational} informational events - No active threats"

st.markdown(f"""
<div class="session-card {card_class}">
    <div class="session-header">
        <span class="session-icon">{icon}</span>
        <span class="session-title">{title}</span>
    </div>
    <div class="session-desc">{desc}</div>
    <div class="session-stats">
        <span>Session logs available</span>
        <span>Real-time updates</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ================= VIEW SESSIONS BUTTON =================
if st.button("View Detailed Session Analysis", use_container_width=True):
    st.switch_page("pages/session_user.py")

# ================= FOOTER =================
st.markdown(f"""
<div class="footer">
    <span>🛡️ IDS Security Console • {datetime.now().strftime('%B %d, %Y')}</span>
</div>
""", unsafe_allow_html=True)
