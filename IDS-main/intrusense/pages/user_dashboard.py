import streamlit as st
import pandas as pd
import os

from common.session import require_login, require_role
from common.sidebar import render_user_sidebar
from common.log_utils import list_sessions
from common.detection_utlis import detect_severity


# ================= PAGE CONFIG =================
st.set_page_config(page_title="IDS Security Console", layout="wide")

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
    st.info("ℹ️ Live stream has not started yet. Showing previous logs if available.")

# ================= LOAD DATA =================
if "live_packets_df" in st.session_state and not st.session_state.live_packets_df.empty:
    df = st.session_state.live_packets_df.copy()
else:
    df = pd.DataFrame(columns=["attack", "severity"])

# ================= METRICS =================
total = len(df)
attack_df = df[df["attack"] != "Normal"] if "attack" in df.columns else pd.DataFrame()
attacks = len(attack_df)

high = (df.get("severity") == "High").sum()
medium = (df.get("severity") == "Medium").sum()
low = (df.get("severity") == "Low").sum()

ratio = round((attacks / total) * 100, 2) if total else 0

user_email = st.session_state.get("email", "user")
user_name = user_email.split("@")[0].capitalize()

# ================= GLOBAL CSS =================
st.markdown("""
<style>

/* HEADER */
.header {
    position: fixed;
    top: 3.5rem;
    left: 0;
    right: 0;
    height: 70px;
    background: linear-gradient(90deg, #020617, #0f172a);
    color: white;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 40px;
    z-index: 1000;
    box-shadow: 0 4px 18px rgba(0,0,0,0.3);
}

.header-title {
    font-size: 20px;
    font-weight: 600;
}

.header-user {
    font-size: 14px;
    color: #cbd5f5;
}

/* PAGE SPACING */
.block-container {
    padding-top: 140px;
    padding-bottom: 80px;
}

/* KPI CARDS */
.card {
    background: white;
    padding: 22px;
    border-radius: 16px;
    box-shadow: 0 8px 28px rgba(0,0,0,0.08);
    border-left: 6px solid #2563eb;
}

.card-title {
    font-size: 14px;
    color: #475569;
}

.card-value {
    font-size: 30px;
    font-weight: 700;
    margin-top: 8px;
    color: #020617;
}

.card.red { border-left-color: #dc2626; }
.card.orange { border-left-color: #f97316; }
.card.green { border-left-color: #16a34a; }
.card.blue { border-left-color: #2563eb; }

/* PANELS */
.threat-panel {
    background: white;
    border-radius: 22px;
    height: 300px;
    padding: 30px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.08);
}

.risk-visual {
    background: linear-gradient(135deg, #020617, #0f172a);
    color: white;
    border-radius: 22px;
    height: 300px;
    padding: 36px;
    box-shadow: 0 15px 35px rgba(0,0,0,0.5);
    display: flex;
    flex-direction: column;
    justify-content: center;
}

.risk-level {
    font-size: 36px;
    font-weight: 800;
}

.risk-text {
    font-size: 14px;
    color: #e5e7eb;
}

/* THREAT BARS */
.threat-row {
    margin-bottom: 18px;
}

.threat-label {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    color: #334155;
    margin-bottom: 6px;
}

.threat-bar {
    height: 14px;
    background: #e5e7eb;
    border-radius: 10px;
    overflow: hidden;
}

.threat-fill {
    height: 100%;
}

.high { background: #dc2626; }
.medium { background: #f59e0b; }
.low { background: #16a34a; }

/* SESSION CTA */
.session-cta {
    width: 100%;
    border-radius: 22px;
    padding: 28px 32px;
    box-shadow: 0 18px 40px rgba(0,0,0,0.35);
    color: white;
}

.cta-high {
    background: linear-gradient(135deg, #7f1d1d, #dc2626);
}
.cta-medium {
    background: linear-gradient(135deg, #78350f, #f59e0b);
}
.cta-low {
    background: linear-gradient(135deg, #064e3b, #10b981);
}
/* SESSION CTA BUTTON — REAL CARD */

.session-cta-btn > button {
    width: 100%;
    padding: 32px 36px;
    border-radius: 22px;
    border: none;
    text-align: left;
    background: linear-gradient(135deg, #7f1d1d, #b91c1c, #dc2626);
    color: white;
    box-shadow: 0 18px 40px rgba(127,29,29,0.55);
    transition: all 0.25s ease;
    line-height: 1.4;
    cursor: pointer;
}

.session-cta-btn > button:hover {
    transform: translateY(-3px);
    box-shadow: 0 26px 60px rgba(127,29,29,0.7);
}

.session-cta-title {
    font-size: 22px;
    font-weight: 700;
}

.session-cta-sub {
    font-size: 14px;
    opacity: 0.9;
    margin-top: 6px;
}
.card-click-wrapper {
    position: relative;
}

.card-click-wrapper button {
    position: absolute;
    inset: 0;
    opacity: 0;
    cursor: pointer;
}
.white-cta-btn > button {
    width: 100%;
    background: white;
    color: #020617;
    border-radius: 14px;
    padding: 12px;
    font-weight: 600;
    border: 1px solid #e5e7eb;
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
}

.white-cta-btn > button:hover {
    background: #f8fafc;
}
.session-action-btn > button {
    width: 100%;
    margin-top: 12px;
    padding: 14px;
    border-radius: 14px;
    background: #ffffff;
    color: #0f172a;
    font-weight: 600;
    border: 1px solid #e5e7eb;
    box-shadow: 0 6px 16px rgba(0,0,0,0.08);
    transition: all 0.2s ease;
}

.session-action-btn > button:hover {
    background: #f8fafc;
    transform: translateY(-1px);
    box-shadow: 0 10px 22px rgba(0,0,0,0.12);
}

</style>
""", unsafe_allow_html=True)

# ================= HEADER =================
st.markdown(f"""
<div class="header">
  <div class="header-title">IDS Security Console</div>
  <div class="header-user">Welcome, {user_name}</div>
</div>
""", unsafe_allow_html=True)

# ================= KPI CARDS =================
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"<div class='card blue'><div class='card-title'>Traffic Analyzed</div><div class='card-value'>{total}</div></div>", unsafe_allow_html=True)
with c2:
    st.markdown(f"<div class='card orange'><div class='card-title'>Threats Detected</div><div class='card-value'>{attacks}</div></div>", unsafe_allow_html=True)
with c3:
    st.markdown(f"<div class='card red'><div class='card-title'>High Severity</div><div class='card-value'>{high}</div></div>", unsafe_allow_html=True)
with c4:
    st.markdown(f"<div class='card green'><div class='card-title'>Attack Ratio</div><div class='card-value'>{ratio}%</div></div>", unsafe_allow_html=True)

# ================= DISTRIBUTION + RISK =================
st.markdown("<br>", unsafe_allow_html=True)
left, right = st.columns(2)

with left:
    total_events = high + medium + low or 1
    st.markdown(f"""
    <div class="threat-panel">
      <div class="threat-row">
        <div class="threat-label"><span>High</span><span>{high}</span></div>
        <div class="threat-bar"><div class="threat-fill high" style="width:{(high/total_events)*100}%"></div></div>
      </div>
      <div class="threat-row">
        <div class="threat-label"><span>Medium</span><span>{medium}</span></div>
        <div class="threat-bar"><div class="threat-fill medium" style="width:{(medium/total_events)*100}%"></div></div>
      </div>
      <div class="threat-row">
        <div class="threat-label"><span>Low</span><span>{low}</span></div>
        <div class="threat-bar"><div class="threat-fill low" style="width:{(low/total_events)*100}%"></div></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

with right:
    if high > 0:
        level, desc, cta_class = "HIGH RISK", "Critical intrusions detected. Immediate response required.", "cta-high"
    elif attacks > 0:
        level, desc, cta_class = "MODERATE RISK", "Suspicious traffic detected. Monitor sessions.", "cta-medium"
    else:
        level, desc, cta_class = "LOW RISK", "Traffic looks clean.", "cta-low"

    st.markdown(f"""
    <div class="risk-visual">
      <div style="font-size:14px;color:#94a3b8;">Overall Risk Status</div>
      <div class="risk-level">{level}</div>
      <div class="risk-text">{desc}</div>
    </div>
    """, unsafe_allow_html=True)

# ================= CTA STATE (ALWAYS DEFINED) =================
if high > 0:
    cta_class = "cta-high"
    subtitle = "Critical intrusions detected. Immediate response required."
elif attacks > 0:
    cta_class = "cta-medium"
    subtitle = "Suspicious activity detected. Inspect session logs."
else:
    cta_class = "cta-low"
    subtitle = "Traffic looks clean. View historical sessions."

st.markdown("<br>", unsafe_allow_html=True)

# 🔴 Session card (UI only)
st.markdown(f"""
<div class="session-cta {cta_class}">
    <div class="session-cta-title"> Detection Sessions</div>
    <div class="session-cta-sub">
        {subtitle}
    </div>
</div>
""", unsafe_allow_html=True)

# ⚪ Button BELOW the card (same width)
st.markdown('<div class="session-action-btn">', unsafe_allow_html=True)
go_sessions = st.button(" Click here to view sessions")
st.markdown('</div>', unsafe_allow_html=True)

if go_sessions:
    st.switch_page("pages/session_user.py")
