import streamlit as st
import pandas as pd
import subprocess
import sys
import json
import time
from pathlib import Path
import plotly.express as px
import numpy as np
import streamlit.components.v1 as components


from database import (
    get_detection_logs,
    get_all_users,
    update_user_status,
    delete_user
)

# ======================================================
# PAGE CONFIG
# ======================================================
st.set_page_config(
    page_title="IDS Admin Control Panel",
    layout="wide"
)

# ======================================================
# SECURITY CHECK
# ======================================================
if "role" not in st.session_state or st.session_state.role != "admin":
    st.error("⛔ Access denied — Admin only")
    st.stop()

# ================= SESSION STATE INIT =================
if "admin_view" not in st.session_state:
    st.session_state.admin_view = None

if "training_done" not in st.session_state:
    st.session_state.training_done = False

if "model_summary" not in st.session_state:
    st.session_state.model_summary = None

if "show_model_info" not in st.session_state:
    st.session_state.show_model_info = False

if "training_done" not in st.session_state:
    st.session_state.training_done = False

if "results" not in st.session_state:
    st.session_state.results = None

if "training_running" not in st.session_state:
    st.session_state.training_running = False

if "results_ready" not in st.session_state:
    st.session_state.results_ready = False

if "poll_training" not in st.session_state:
    st.session_state.poll_training = False




# =========================
# PATHS
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent / "ml"
STATUS_FILE = BASE_DIR / "training_status.json"
RESULTS_FILE = BASE_DIR / "training_results.json"
TOTAL_EPOCHS = 2   # MUST MATCH train.py

# ======================================================
import base64
from pathlib import Path

def set_bg(image_path):
    img = Path(image_path)
    if not img.exists():
        st.error(f"Background image not found: {image_path}")
        return

    encoded = base64.b64encode(img.read_bytes()).decode()

    st.markdown(
        f"""
        <style>
        .stApp {{
            background: url("data:image/jpg;base64,{encoded}") no-repeat center center fixed;
            background-size: cover;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )
def set_plain_bg():
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #020617, #000000) !important;
            background-attachment: fixed;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
if st.session_state.get("admin_view") == "training":
    set_plain_bg()
else:
    set_bg("assets/admin_bg.jpg")

# ======================================================
# CYBER BACKGROUND + UI
# ======================================================
st.markdown("""
<style>



/* ===== HEADER ===== */
.header {
    background: rgba(0,0,0,0.88);
    padding: 22px;
    border-radius: 14px;
    margin-bottom: 10px;
    border: 1px solid #38bdf8;
    box-shadow: 0 0 25px rgba(56,189,248,0.6);
}

.header h1 {
    margin: 0;
    text-align: center;
    font-size: 36px;
    font-weight: 800;
    color: #7dd3fc;
    text-shadow: 0 0 18px rgba(56,189,248,0.9);
}

/* ===== BUTTONS ===== */
.admin-btn button {
    width: 100%;
    height: 80px;
    font-size: 22px !important;
    font-weight: 700 !important;
    border-radius: 18px !important;
    margin-bottom: 25px;
    background: linear-gradient(135deg, #020617, #020617);
    color: #7dd3fc !important;
    border: 1px solid #38bdf8 !important;
    box-shadow: 0 0 22px rgba(56,189,248,0.55);
}

.admin-btn button:hover {
    background: linear-gradient(135deg, #0ea5e9, #0284c7);
    color: black !important;
}

/* ===== GLASS PANEL ===== */
.glass {
    background: rgba(2, 6, 23, 0.78);
    backdrop-filter: blur(14px);
    border-radius: 18px;
    padding: 28px;
    border: 1px solid rgba(56,189,248,0.5);
    box-shadow: 0 0 30px rgba(56,189,248,0.4);
    color: #e5f6ff;
}

/* ===== USER CARD ===== */
.user-card {
    background: rgba(2, 6, 23, 0.92);
    padding: 20px;
    border-radius: 14px;
    margin-bottom: 18px;
    border: 1px solid rgba(56,189,248,0.4);
}

.user-card h4 {
    color: #7dd3fc;
    margin-bottom: 8px;
}

.user-card p {
    color: #e0f2fe;
    font-size: 16px;
    font-weight: 600;
}
/* ===== TRAINING PIPELINE ===== */
.pipeline-title {
    text-align: center;
    font-size: 28px;
    font-weight: 800;
    color: #7dd3fc;
    text-shadow: 0 0 12px rgba(56,189,248,0.9);
    margin-bottom: 20px;
}

.pipeline-step {
    text-align: center;
    padding: 12px;
}

.pipeline-step h3 {
    color: #38bdf8;
    font-size: 20px;
    margin-bottom: 6px;
}

.pipeline-step p {
    color: #e0f2fe;
    font-size: 14px;
    margin-bottom: 10px;
}

.pipeline-divider {
    height: 3px;
    background: linear-gradient(90deg, #38bdf8, #7c3aed);
    border-radius: 10px;
    margin: 10px 0 25px 0;
}

/* ===== MODEL ARCHITECTURE TITLE FIX ===== */
.model-title {
    color: #ffffff;          /* same blue you are using */
    font-size: 26px;
    font-weight: 800;
    text-shadow: 0 0 12px rgba(56,189,248,0.8);
    margin: 30px 0 20px 0;
}

/* ===== MODEL METRIC CARDS ===== */
.metric-card {
    background: linear-gradient(145deg, rgba(2,6,23,0.9), rgba(2,6,23,0.7));
    border: 1px solid rgba(56,189,248,0.8);
    border-radius: 16px;
    padding: 18px;
    text-align: center;
    box-shadow: 0 0 18px rgba(56,189,248,0.6);
}

.metric-card h4 {
    color: #7dd3fc;
    margin-bottom: 6px;
    font-size: 16px;
}

.metric-card h2 {
    color: #ffffff;
    font-size: 26px;
    font-weight: 800;
}

/* ===== IDS STYLE TABLE ===== */
/* ===== IDS HTML TABLE ===== */
.arch-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 18px;
    background: rgba(2,6,23,0.75);
    border-radius: 14px;
    overflow: hidden;
    box-shadow: 0 0 25px rgba(56,189,248,0.35);
}

.arch-table thead {
    background: rgba(2,6,23,0.95);
}

.arch-table th {
    padding: 14px;
    text-align: center;
    color: #7dd3fc;
    font-size: 15px;
    border-bottom: 1px solid #38bdf8;
}

.arch-table td {
    padding: 12px;
    text-align: center;
    color: #e0f2fe;
    font-size: 14px;
}

.arch-table tbody tr {
    transition: background 0.25s ease;
}

.arch-table tbody tr:hover {
    background: rgba(56,189,248,0.15);
}

            /* ===== CUSTOM PROGRESS BAR ===== */
div[data-testid="stProgress"] > div > div {
    background: linear-gradient(
        90deg,
        #38bdf8,
        #7c3aed
    ) !important;
}

div[data-testid="stProgress"] {
    height: 12px;
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)

# ======================================================
# HEADER
# ======================================================
st.markdown("""
<div class="header">
    <h1>🛡 IDS Admin Control Panel</h1>
</div>
""", unsafe_allow_html=True)


# ======================================================
# DASHBOARD CARDS (CENTER)
# ======================================================
if st.session_state.admin_view is None:
    c1, c2, c3 = st.columns(3)

    # -------- MODEL TRAINING CARD --------
    with c1:
        st.markdown("""
        <div class="glass" style="text-align:center;">
            <h2>🤖 Model Training</h2>
            <p>Steps to train IDS ML model</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Open Model Training", use_container_width=True):
            st.session_state.admin_view = "training"
            st.rerun()

    # -------- USERS CARD --------
    with c2:
        st.markdown("""
        <div class="glass" style="text-align:center;">
            <h2>👥 Users</h2>
            <p>Manage users, block or delete accounts</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Open Users Management", use_container_width=True):
            st.session_state.admin_view = "users"
            st.rerun()

    # -------- LOGS CARD --------
    with c3:
        st.markdown("""
        <div class="glass" style="text-align:center;">
            <h2>📊 Detection Logs</h2>
            <p>View intrusion detection activity</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Open Detection Logs", use_container_width=True):
            st.session_state.admin_view = "logs"
            st.rerun()

# ================= BACK BUTTON =================
if st.session_state.admin_view is not None:
    if st.button("⬅ Back to Dashboard"):
        st.session_state.admin_view = None
        st.session_state.results = None
        st.session_state.training_done = False
        st.session_state.model_summary = None   # 👈 add this
        st.rerun()


# ================= USERS =================
if st.session_state.admin_view == "users":
    col1, col2, col3 = st.columns([1, 3, 1])

    with col2:
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        st.subheader("👥 Registered Users")


    users = get_all_users()

    if users:
        for user_id, email, role, status in users:

            # ❌ Admin cannot be modified
            if role == "admin":
                continue

            st.markdown(f"""
            <div class="user-card">
                <h4>{email}</h4>
                <p>Role: {role}</p>
                <p>Status: {status}</p>
            </div>
            """, unsafe_allow_html=True)

            c1, c2 = st.columns(2)

            with c1:
                if st.button(f"🗑 Delete", key=f"del_{user_id}"):
                    delete_user(user_id)
                    st.success("User deleted successfully")
                    st.rerun()

            with c2:
                if status == "active":
                    if st.button(f"🚫 Block", key=f"blk_{user_id}"):
                        update_user_status(user_id, "blocked")
                        st.warning("User blocked")
                        st.rerun()
                else:
                    if st.button(f"✅ Unblock", key=f"unblk_{user_id}"):
                        update_user_status(user_id, "active")
                        st.success("User unblocked")
                        st.rerun()

    else:
        st.info("No users found.")

    st.markdown('</div>', unsafe_allow_html=True)

# ================= LOGS =================
if st.session_state.admin_view == "logs":
    col1, col2, col3 = st.columns([1, 4, 1])

    with col2:
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        st.subheader("📊 Detection Logs")

        logs = get_detection_logs()

        if logs:
            df = pd.DataFrame(
                logs,
                columns=["Email", "File", "Type", "Records", "Time"]
            )

            st.dataframe(
                df,
                use_container_width=True,
                height=420
            )
        else:
            st.info("No detection logs available.")

        st.markdown('</div>', unsafe_allow_html=True)

import re

def parse_model_summary(summary_text):
    lines = summary_text.splitlines()

    model_name = "Unknown"
    total_params = trainable_params = non_trainable_params = "0"
    rows = []

    for line in lines:
        # Model name
        if line.strip().startswith('Model:'):
            model_name = line.split('"')[1]

        # Params
        if 'Total params:' in line:
            total_params = line.split(':')[-1].strip()
        if 'Trainable params:' in line:
            trainable_params = line.split(':')[-1].strip()
        if 'Non-trainable params:' in line:
            non_trainable_params = line.split(':')[-1].strip()

        # Layer rows (regex based)
        match = re.search(
            r'^(\w+).*?\((None,\s*\d+)\)\s+(\d+)$',
            line.strip()
        )
        if match:
            layer = match.group(1)
            output_shape = match.group(2)
            params = match.group(3)
            rows.append([layer, output_shape, params])

    return model_name, total_params, trainable_params, non_trainable_params, rows

# ================= MODEL TRAINING =================
def run_script(script_path):
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True
        )

        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += "\n" + result.stderr

        return output.strip() if output else "✅ Script executed successfully."

    except Exception as e:
        return f"❌ Error: {str(e)}"

# ================= MODEL TRAINING =================
if st.session_state.admin_view == "training":

    st.markdown("""
    <div class="pipeline-title">🤖 IDS Model Training Pipeline</div>
    <div class="pipeline-divider"></div>
    """, unsafe_allow_html=True)

    s1, s2, s3 = st.columns(3)

    # ================= STEP 1 =================
    with s1:
        st.markdown("""
        <div class="pipeline-step">
            <h3>1️⃣ Preprocessing</h3>
            <p>Prepare & clean dataset</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("▶ Run Preprocessing", key="btn_preprocess", use_container_width=True):
            with st.spinner("Running preprocessing..."):
                output = run_script("ml/preprocessing.py")
                st.code(output, language="text")

    # ================= STEP 2 =================
    with s2:
        st.markdown("""
        <div class="pipeline-step">
            <h3>2️⃣ Model Build</h3>
            <p>BiLSTM Architecture</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("▶ Build Model", key="btn_build_model", use_container_width=True):
            with st.spinner("Building model..."):
                raw_summary = run_script("ml/model.py")
                st.session_state.model_summary = raw_summary
                st.session_state.show_model_info = True
                st.rerun()


    # ================= STEP 3 =================
    with s3:
        st.markdown("""
        <div class="pipeline-step">
            <h3>3️⃣ Training</h3>
            <p>Train IDS model</p>
        </div>
        """, unsafe_allow_html=True)

        if st.button(
            "▶ Train Model",
            key="train_model_pipeline",
            use_container_width=True
        ):

            if STATUS_FILE.exists():
                try:
                    data = json.loads(STATUS_FILE.read_text())
                except Exception:
                    time.sleep(1)
                    st.rerun()
                    st.stop()

            if RESULTS_FILE.exists():
                RESULTS_FILE.unlink()

            subprocess.Popen(
                [sys.executable, str(BASE_DIR / "train.py")],
                cwd=str(BASE_DIR)
            )

            st.session_state.training_running = True
            st.session_state.training_done = False
            st.session_state.results = None

            st.rerun()

    # ================= RESET =================
    if st.button("Reset Training Pipeline", key="btn_reset_pipeline"):

        if STATUS_FILE.exists():
            STATUS_FILE.unlink()

        st.session_state.model_summary = None
        st.session_state.training_running = False
        st.session_state.training_done = False
        st.session_state.results = None

        st.rerun()

# ================= MODEL ARCHITECTURE DISPLAY =================
if st.session_state.show_model_info and st.session_state.model_summary:

    model_name, total_p, trainable_p, non_trainable_p, rows = parse_model_summary(
        st.session_state.model_summary
    )

    # -------- PARAM CARDS --------
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Total Parameters</h4>
            <h2>{total_p}</h2>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Trainable</h4>
            <h2>{trainable_p}</h2>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Non-Trainable</h4>
            <h2>{non_trainable_p}</h2>
        </div>
        """, unsafe_allow_html=True)

    # -------- LAYER TABLE --------

    components.html(
        f"""
        <style>
            .glass-box {{
                background: rgba(2,6,23,0.85);
                backdrop-filter: blur(14px);
                border-radius: 18px;
                padding: 26px;
                border: 1px solid rgba(56,189,248,0.55);
                box-shadow: 0 0 35px rgba(56,189,248,0.35);
                margin-top: 30px;
            }}

            .arch-title {{
                font-size: 24px;
                font-weight: 800;
                color: #7dd3fc;
                text-shadow: 0 0 12px rgba(56,189,248,0.8);
                margin-bottom: 18px;
                display: flex;
                align-items: center;
                gap: 10px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: rgba(2,6,23,0.75);
                border-radius: 14px;
                overflow: hidden;
            }}

            thead {{
                background: rgba(2,6,23,0.95);
                position: sticky;
                top: 0;
                z-index: 1;
            }}

            th {{
                padding: 14px;
                text-align: center;
                color: #7dd3fc;
                font-size: 15px;
                border-bottom: 1px solid #38bdf8;
            }}

            td {{
                padding: 12px;
                text-align: center;
                color: #e0f2fe;
                font-size: 14px;
            }}

            tbody tr {{
                transition: all 0.25s ease;
            }}

            tbody tr:hover {{
                background: rgba(56,189,248,0.18);
                transform: scale(1.01);
            }}
        </style>

        <div class="glass-box">
            <div class="arch-title">📐 Layer-wise Architecture</div>

            <table>
                <thead>
                    <tr>
                        <th>Layer</th>
                        <th>Output Shape</th>
                        <th>Parameters</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([
                        f"<tr><td>{l}</td><td>{s}</td><td>{p}</td></tr>"
                        for l, s, p in rows
                    ])}
                </tbody>
            </table>
        </div>
        """,
        height=460,
    )



    st.markdown('</div>', unsafe_allow_html=True)

    # show only once
    st.session_state.show_model_info = False


