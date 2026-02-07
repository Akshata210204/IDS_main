import streamlit as st
import pandas as pd
import time
import altair as alt

from common.sidebar import render_user_sidebar
from common.session import require_login
from common.detection_utlis import detect_severity
from common.live_capture import live_packet_stream
from common.log_utils import start_new_session, save_log


# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="Intrusion Detection", layout="wide")

# ---------------- AUTH ----------------
require_login()

render_user_sidebar()

PROTOCOL_MAP = {
    1: "TCP",
    2: "UDP",
    3: "ICMP"
}

# ---------------- GLOBAL CSS ----------------
st.markdown("""
<style>

/* ---------- HEADER ---------- */
.header {
    position: fixed;
    top: 3.5rem;
    left: 0;
    right: 0;
    height: 80px;
    background: linear-gradient(90deg, #020617, #0f172a);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;   /* 👈 CENTER CONTENT */
    text-align: center;        /* 👈 CENTER TEXT */
    z-index: 1000;
    box-shadow: 0 4px 18px rgba(0,0,0,0.3);
}


.header-title {
    font-size: 20px;
    font-weight: 700;
}

.header-subtitle {
    font-size: 13px;
    color: #cbd5f5;
    margin-top: 2px;
}

/* ---------- PAGE SPACING ---------- */
.block-container {
    padding-top: 150px;
    padding-bottom: 90px;
}

/* ---------- FOOTER ---------- */
.footer {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    height: 60px;
    background: #020617;
    color: #94a3b8;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    z-index: 1000;
}
</style>
""", unsafe_allow_html=True)

# ---------------- CSS ----------------
st.markdown("""
<style>
[data-testid="stAppViewContainer"]{
    background:#ffffff;
}
.card{
    background:#ffffff;
    padding:18px;
    border-radius:16px;
    text-align:center;
    border:1px solid #d1fae5;
    box-shadow:0 8px 20px rgba(0,0,0,0.06);
}
</style>
""", unsafe_allow_html=True)


# ---------------- SESSION STATE INIT ----------------
if "live_running" not in st.session_state:
    st.session_state.live_running = False
if "live_index" not in st.session_state:
    st.session_state.live_index = 0
if "live_generator" not in st.session_state:
    st.session_state.live_generator = None
if "chart_data" not in st.session_state:
    st.session_state.chart_data = pd.DataFrame(
        columns=["packet", "severity", "attack", "confidence"]
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
            "attack",
            "severity",
            "confidence"
        ]
    )



# ================= HEADER =================
st.markdown("""
<div class="header">
    <div>
        <div class="header-title">Intrusion Detection System</div>
        <div class="header-subtitle">Live and Offline Network Threat Monitoring</div>
    </div>
</div>
""", unsafe_allow_html=True)


        # =====================================================
    # LIVE STREAM
    # =====================================================
st.subheader("Live Intrusion Detection")
chart_placeholder = st.container()

colA, colB = st.columns(2)

with colA:
    if st.button("Start Live Detection"):
        st.session_state.live_running = True
        st.session_state.live_generator = live_packet_stream()

        st.session_state.chart_data = st.session_state.chart_data.iloc[0:0]
        st.session_state.live_packets_df = st.session_state.live_packets_df.iloc[0:0]

        # ✅ START NEW SESSION
        st.session_state.current_log_file = start_new_session(
            st.session_state.get("email")
        )
        st.rerun()
with colB:
    if st.button("Stop Live Stream"):
        st.session_state.live_running = False
        st.session_state.live_generator = None


# Auto refresh every 1 second while live is running

        
st.session_state.stream_busy = False



def render_chart():
    if st.session_state.chart_data.empty:
        return

    base = alt.Chart(st.session_state.chart_data)
    line = base.mark_line(strokeWidth=3, color="#39ff14").encode(
        x=alt.X("packet:Q",  title="Packet Number", scale=alt.Scale(nice=False)),
        y=alt.Y(
            "severity:Q",
            scale=alt.Scale(domain=[0.5, 3.5]),
            axis=alt.Axis(
                values=[1, 2, 3],
                labelExpr="datum.value == 1 ? 'Low' : datum.value == 2 ? 'Medium' : 'High'"
            )
        )
    )

    points = base.mark_circle(size=90).encode(
        x="packet:Q",
        y="severity:Q",
        color="attack:N",
        tooltip=["packet", "attack", "confidence"]
    )

    chart_placeholder.altair_chart(
        (line + points).properties(height=380),
        use_container_width=True
    )

# Always render chart
render_chart()

# ================= LIVE STREAM EXECUTION =================
if st.session_state.live_running and st.session_state.live_generator:

    try:
        event = next(st.session_state.live_generator)
        save_log(
            st.session_state.current_log_file,
            {
                "packet": event["row"],
                **event["features"], 
                "attack": event["prediction"],
                "severity": event["severity"],
                "confidence": event["confidence"]
            }
        )
        sev_num = 1 if event["severity"] == "Low" else 2 if event["severity"] == "Medium" else 3

        # Chart data
        st.session_state.chart_data.loc[len(st.session_state.chart_data)] = {
            "packet": event["row"],
            "severity": sev_num,
            "attack": event["prediction"],
            "confidence": event["confidence"]
        }

        # ✅ Live table data
        row_data = {
            "packet": event["row"],
            **event["features"],     # 👈 THIS IS THE KEY LINE
            "attack": event["prediction"],
            "severity": event["severity"],
            "confidence": event["confidence"]
        }

        st.session_state.live_packets_df.loc[len(st.session_state.live_packets_df)] = row_data

        
        time.sleep(1)
        st.rerun()

    except StopIteration:
        st.session_state.live_running = False
        st.session_state.live_generator = None

    # =====================================================
# SHOW OPTIONS ONLY WHEN LIVE STREAM IS STOPPED
# =====================================================
live_df = st.session_state.live_packets_df

if not st.session_state.live_running and not live_df.empty:

    st.divider()
    tab_row, tab_search, tab_severity, tab_results = st.tabs([
        "Predict by Packet Number",
        "Search Attack",
        "Severity View",
        "Full Results"
    ])

    # ---------------- PREDICT BY ROW ----------------
    with tab_row:
        st.subheader("Predict by Packet Number")

        if live_df.empty:
            st.info("Start live stream to see predictions")
        else:
            row_no = st.number_input(
                "Select Packet Number",
                min_value=1,
                max_value=len(live_df),
                value=1,
                step=1
            )

            # Convert user-friendly (1-based) to pandas (0-based)
            row = live_df.iloc[row_no - 1]

            sev = detect_severity(row["attack"])

            col1, col2, col3 = st.columns(3)

            with col1:
                st.markdown(f"""
                <div class="card">
                    <h2>{row['attack']}</h2>
                    <h2>{round(row['confidence'] * 100, 2)}%</h2>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown(f"""
                <div class="card">
                    <h4>Severity</h4>
                    <h2>{sev}</h2>
                </div>
                """, unsafe_allow_html=True)

            with col3:
                st.markdown(f"""
                <div class="card">
                    <h4>Confidence</h4>
                    <h2>{round(row['confidence'] * 100, 2)}%</h2>
                </div>
                """, unsafe_allow_html=True)



    # ---------------- SEARCH ATTACK ----------------
    with tab_search:
        st.subheader("Search Attack (Live Data Only)")

        if live_df.empty:
            st.info("No live data yet")
        else:
            query = st.text_input("Enter attack name").lower()

            if query:
                result = live_df[
                    live_df["attack"].str.lower().str.contains(query)
                ].copy()

                if result.empty:
                    st.warning("No matching attacks found")
                else:
                    result["Row"] = result.index + 1
                    result["Severity"] = result["attack"].apply(detect_severity)
                    result["Confidence (%)"] = (result["confidence"] * 100).round(2)

                    st.dataframe(
                        result[["Row", "attack", "Severity", "Confidence (%)"]],
                        use_container_width=True
                    )

    # ---------------- SEVERITY VIEW ----------------
    with tab_severity:
        st.subheader("Severity Distribution (Live Data)")

        if live_df.empty:
            st.info("No live data yet")
        else:
            temp_df = live_df.copy()
            temp_df["Severity"] = temp_df["attack"].apply(detect_severity)

            severity_counts = temp_df["Severity"].value_counts().reset_index()
            severity_counts.columns = ["Severity", "Count"]

            pie = alt.Chart(severity_counts).mark_arc(innerRadius=60).encode(
                theta="Count:Q",
                color="Severity:N",
                tooltip=["Severity", "Count"]
            ).properties(height=350)

            st.altair_chart(pie, use_container_width=True)


    # ---------------- FULL RESULTS ----------------
    with tab_results:
        st.subheader("Full Results (Live Data Only)")

        if live_df.empty:
            st.info("No live data yet")
        else:
            df_show = live_df.reset_index(drop=True)
            df_show.index = df_show.index + 1

            # ---- UI ONLY: map protocol numbers to names ----
            df_display = df_show.copy()

            df_display["protocol_type"] = df_display["protocol_type"].map(
                lambda x: PROTOCOL_MAP.get(x, "OTHER")
            )

            st.dataframe(df_display, use_container_width=True)


            csv = df_show.to_csv(index=True).encode("utf-8")

            st.download_button(
                label="Download Results as CSV",
                data=csv,
                file_name="ids_live_results.csv",
                mime="text/csv"
            )



# ================= FOOTER =================
st.markdown("""
<div class="footer">
Intrusion Detection System · Live Detection Console · 2026
</div>
""", unsafe_allow_html=True)
