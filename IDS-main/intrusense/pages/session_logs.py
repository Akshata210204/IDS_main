import streamlit as st
import pandas as pd
from common.session import require_login, require_role
from common.sidebar import render_user_sidebar

# ================= AUTH =================
require_login()
require_role("user")
render_user_sidebar()

# ================= PAGE CONFIG =================
st.set_page_config(page_title="Session Logs", layout="wide")

PROTOCOL_MAP = {
    1: "TCP",
    2: "UDP",
    3: "ICMP"
}

# ================= CSS (REUSED) =================
st.markdown("""
<style>
.block-container {
    padding-top: 120px;
    padding-bottom: 80px;
}

.card {
    background: white;
    padding: 22px;
    border-radius: 16px;
    box-shadow: 0 8px 28px rgba(0,0,0,0.08);
    border-left: 6px solid #2563eb;
}

.card.red { border-left-color: #dc2626; }
.card.orange { border-left-color: #f97316; }
.card.green { border-left-color: #16a34a; }
.card.blue { border-left-color: #2563eb; }

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
</style>
""", unsafe_allow_html=True)

# ================= BACK BUTTON =================
col_back, col_title = st.columns([1, 6])

with col_back:
    if st.button("⬅ Back"):
        st.session_state.selected_session_file = None
        st.switch_page("pages/user_dashboard.py")

with col_title:
    st.subheader("📄 Session Logs")

# ================= LOAD SESSION =================
if "selected_session_file" not in st.session_state or not st.session_state.selected_session_file:
    st.warning("No session selected.")
    st.stop()

try:
    session_df = pd.read_csv(st.session_state.selected_session_file)
except Exception:
    st.error("Unable to load session file.")
    st.stop()

if session_df.empty:
    st.info("No logs found in this session.")
    st.stop()

# ================= KPIs =================
s_total = len(session_df)
severity_col = session_df["severity"].astype(str)

s_high = (severity_col == "High").sum()
s_medium = (severity_col == "Medium").sum()
s_low = (severity_col == "Low").sum()

k1, k2, k3, k4 = st.columns(4)

with k1:
    st.markdown(f"""
    <div class="card blue">
        <div class="card-title">Packets</div>
        <div class="card-value">{s_total}</div>
    </div>
    """, unsafe_allow_html=True)

with k2:
    st.markdown(f"""
    <div class="card red">
        <div class="card-title">High Severity</div>
        <div class="card-value">{s_high}</div>
    </div>
    """, unsafe_allow_html=True)

with k3:
    st.markdown(f"""
    <div class="card orange">
        <div class="card-title">Medium Severity</div>
        <div class="card-value">{s_medium}</div>
    </div>
    """, unsafe_allow_html=True)

with k4:
    st.markdown(f"""
    <div class="card green">
        <div class="card-title">Low Severity</div>
        <div class="card-value">{s_low}</div>
    </div>
    """, unsafe_allow_html=True)

# ================= TABLE =================
st.markdown("### 📊 Detection Details")

def severity_badge(sev):
    if sev == "High":
        return "🔴 High"
    if sev == "Medium":
        return "🟠 Medium"
    return "🟢 Low"

styled_df = session_df.copy()

# Protocol mapping (UI only)
if "protocol_type" in styled_df.columns:
    styled_df["protocol_type"] = styled_df["protocol_type"].map(
        lambda x: PROTOCOL_MAP.get(x, "OTHER")
    )

# Severity badge
styled_df["severity"] = styled_df["severity"].apply(severity_badge)

# Column order
preferred_order = [
    "timestamp",
    "packet",
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "attack",
    "severity",
    "confidence"
]

existing_cols = [c for c in preferred_order if c in styled_df.columns]
styled_df = styled_df[existing_cols]

styled_df.index = styled_df.index + 1

st.dataframe(
    styled_df,
    use_container_width=True,
    height=460
)


# ================= DOWNLOAD =================
csv = styled_df.to_csv(index=True).encode("utf-8")

st.download_button(
    label="Download Session Logs",
    data=csv,
    file_name="session_logs.csv",
    mime="text/csv"
)
