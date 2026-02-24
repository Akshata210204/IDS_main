import streamlit as st
import pandas as pd
import os
import glob
from datetime import datetime
from common.session import require_login, require_role
from common.sidebar import render_user_sidebar
from common.log_utils import list_sessions

# ================= AUTH =================
require_login()
require_role("user")
render_user_sidebar()

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="Session Logs", 
    layout="wide",
    page_icon="📋"
)

PROTOCOL_MAP = {
    1: "TCP",
    2: "UDP",
    3: "ICMP"
}

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

/* Header Styles */
.glass-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1.5rem 2rem;
    border-radius: 20px;
    margin-bottom: 2rem;
    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
}

.header-title {
    font-size: 2rem;
    font-weight: 700;
    color: white;
    margin-bottom: 0.3rem;
}

.header-subtitle {
    font-size: 1rem;
    color: rgba(255,255,255,0.9);
}

.header-badge {
    background: rgba(255,255,255,0.2);
    padding: 0.3rem 1rem;
    border-radius: 50px;
    color: white;
    font-size: 0.8rem;
    display: inline-block;
    margin-top: 0.5rem;
}

/* Stats Cards */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1rem;
    margin: 1.5rem 0;
}

.stat-card {
    background: white;
    padding: 1.2rem;
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
    font-size: 0.8rem;
    color: #64748b;
    text-transform: uppercase;
}

.stat-value {
    font-size: 1.8rem;
    font-weight: 700;
    color: #1e293b;
    margin: 0.2rem 0;
}

/* Table Container */
.table-container {
    background: white;
    border-radius: 20px;
    padding: 1.5rem;
    margin: 1.5rem 0;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    border: 1px solid #eef2f6;
    overflow-x: auto;
}

.section-title {
    font-size: 1.2rem;
    font-weight: 600;
    color: #1e293b;
    margin-bottom: 1rem;
}

.section-title span {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 0.2rem 1rem;
    border-radius: 50px;
    font-size: 0.8rem;
    margin-left: 1rem;
}

/* Severity Badges */
.severity-critical {
    background: #7f1d1d20;
    color: #7f1d1d;
    padding: 0.2rem 0.8rem;
    border-radius: 50px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.severity-high {
    background: #fee2e2;
    color: #dc2626;
    padding: 0.2rem 0.8rem;
    border-radius: 50px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.severity-medium {
    background: #fed7aa;
    color: #d97706;
    padding: 0.2rem 0.8rem;
    border-radius: 50px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.severity-low {
    background: #dcfce7;
    color: #16a34a;
    padding: 0.2rem 0.8rem;
    border-radius: 50px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

.severity-info {
    background: #e2e8f0;
    color: #475569;
    padding: 0.2rem 0.8rem;
    border-radius: 50px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

/* Confidence Badge */
.confidence-badge {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 0.2rem 0.8rem;
    border-radius: 50px;
    font-size: 0.8rem;
    font-weight: 600;
    display: inline-block;
}

/* Download Button */
.stDownloadButton > button {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
    color: white !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 0.75rem 2rem !important;
    font-weight: 600 !important;
    width: 100%;
    margin-top: 1rem;
}

/* Empty State */
.empty-state {
    text-align: center;
    padding: 4rem 2rem;
    background: white;
    border-radius: 20px;
    border: 2px dashed #e2e8f0;
    margin: 2rem 0;
}

.empty-state-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
    opacity: 0.5;
}

.empty-state-title {
    font-size: 1.3rem;
    font-weight: 600;
    color: #334155;
    margin-bottom: 0.5rem;
}

/* Footer */
.footer {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
    border-radius: 15px;
    color: white;
    text-align: center;
    margin-top: 2rem;
    font-size: 0.9rem;
}
</style>
""", unsafe_allow_html=True)

# ================= HEADER =================
user_email = st.session_state.get("email", "user")
user_name = user_email.split("@")[0].capitalize() if "@" in user_email else user_email.capitalize()

st.markdown(f"""
<div class="glass-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <div class="header-title">Session Logs</div>
            <div class="header-subtitle">Complete detection results for {user_name}</div>
            <div class="header-badge">
                <span>Full Analysis</span> • 
                <span>All Severities</span>
            </div>
        </div>
        <div style="text-align: right; color: white;">
            <div style="font-size: 0.9rem;">{datetime.now().strftime('%B %d, %Y')}</div>
            <div style="font-size: 1.2rem; font-weight: 600;">{datetime.now().strftime('%I:%M %p')}</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ================= BACK BUTTON =================
col1, col2 = st.columns([1, 11])
with col1:
    if st.button("← Back to Sessions"):
        st.session_state.selected_session_file = None
        st.switch_page("pages/session_user.py")

# ================= GET USER SESSIONS =================
sessions, user_path = list_sessions(user_email)

if not sessions:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon">📭</div>
        <div class="empty-state-title">No Sessions Found</div>
        <div class="empty-state-text">You haven't saved any detection sessions yet</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ================= GET THE LATEST SESSION =================
# Sort sessions by timestamp (assuming they're already sorted or we can sort them)
latest_session = sessions[0] if sessions else None  # Get the first/most recent session

if not latest_session:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon">📭</div>
        <div class="empty-state-title">No Sessions Found</div>
        <div class="empty-state-text">You haven't saved any detection sessions yet</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

selected_filename = latest_session['filename']
selected_filepath = os.path.join(user_path, selected_filename)

# Store in session state
if st.session_state.get("selected_session_file") != selected_filepath:
    st.session_state.selected_session_file = selected_filepath
    st.rerun()

# ================= LOAD AND DISPLAY SESSION =================
if st.session_state.selected_session_file and os.path.exists(st.session_state.selected_session_file):
    try:
        # Load the CSV
        df = pd.read_csv(st.session_state.selected_session_file)
        
        if df.empty:
            st.warning("This session file is empty")
            st.stop()
        
        # ================= SESSION INFO =================
        st.markdown(f"""
        <div style="background: white; border-radius: 15px; padding: 1rem; margin: 1rem 0; border: 1px solid #eef2f6;">
            <span style="color: #64748b;">Session File: </span>
            <span style="color: #667eea; font-weight: 600;">{selected_filename}</span>
            <span style="color: #64748b; margin-left: 2rem;">Session Time: </span>
            <span style="color: #667eea; font-weight: 600;">{latest_session['timestamp']}</span>
            <span style="color: #64748b; margin-left: 2rem;">Records: </span>
            <span style="color: #667eea; font-weight: 600;">{len(df)}</span>
            <span style="color: #64748b; margin-left: 2rem;">Features: </span>
            <span style="color: #667eea; font-weight: 600;">{len(df.columns)}</span>
        </div>
        """, unsafe_allow_html=True)
        
        # ================= STATS CARDS =================
        if "severity" in df.columns:
            severity_col = df["severity"].astype(str)
            
            s_critical = (severity_col == "Critical").sum()
            s_high = (severity_col == "High").sum()
            s_medium = (severity_col == "Medium").sum()
            s_low = (severity_col == "Low").sum()
            s_info = (severity_col == "Informational").sum()
            s_total = len(df)
            
            st.markdown('<div class="stats-grid">', unsafe_allow_html=True)
            
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                st.markdown(f"""
                <div class="stat-card info">
                    <div class="stat-label">Total</div>
                    <div class="stat-value">{s_total}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                <div class="stat-card critical">
                    <div class="stat-label">Critical</div>
                    <div class="stat-value">{s_critical}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                st.markdown(f"""
                <div class="stat-card high">
                    <div class="stat-label">High</div>
                    <div class="stat-value">{s_high}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                st.markdown(f"""
                <div class="stat-card medium">
                    <div class="stat-label">Medium</div>
                    <div class="stat-value">{s_medium}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col5:
                st.markdown(f"""
                <div class="stat-card low">
                    <div class="stat-label">Low/Info</div>
                    <div class="stat-value">{s_low + s_info}</div>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
        
        # ================= DATA TABLE =================
        st.markdown('<div class="table-container">', unsafe_allow_html=True)
        st.markdown("""
        <div class="section-title">
            Complete Detection Results
            <span>All Fields</span>
        </div>
        """, unsafe_allow_html=True)
        
        # Format the dataframe for display
        display_df = df.copy()
        
        # Map protocol numbers to names
        if "protocol_type" in display_df.columns:
            display_df["protocol_type"] = display_df["protocol_type"].map(PROTOCOL_MAP).fillna(display_df["protocol_type"])
        
        # Format confidence as percentage
        if "confidence" in display_df.columns:
            display_df["confidence"] = (display_df["confidence"] * 100).round(1).astype(str) + "%"
        
        # Display the dataframe
        st.dataframe(display_df, use_container_width=True, height=500)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        
        # ================= DOWNLOAD BUTTON =================
        col_down1, col_down2, col_down3 = st.columns([1, 2, 1])
        with col_down2:
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Session Logs (CSV)",
                data=csv,
                file_name=f"session_{selected_filename}",
                mime="text/csv"
            )
        
    except Exception as e:
        st.error(f"Error loading session: {str(e)}")
        st.exception(e)
else:
    st.error("Selected session file not found")

# ================= FOOTER =================
st.markdown("""
<div class="footer">
    <span>🛡️ Intrusion Detection System • Session Logs</span>
</div>
""", unsafe_allow_html=True)
