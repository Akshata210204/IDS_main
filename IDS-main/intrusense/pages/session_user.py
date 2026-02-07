import streamlit as st
import os
from common.session import require_login, require_role
from common.sidebar import render_user_sidebar
from common.log_utils import list_sessions, delete_session

# ================= PAGE CONFIG =================
st.set_page_config(page_title="Detection Sessions", layout="wide")

# ================= AUTH =================
require_login()
require_role("user")
render_user_sidebar()

user_email = st.session_state.get("email")

# ================= BACK BUTTON (TOP, NOT NAVBAR) =================
col_back, col_space = st.columns([1, 10])
with col_back:
    if st.button("⬅ Back"):
        st.switch_page("pages/user_dashboard.py")

# ================= TITLE =================
st.title("📜 Detection Sessions")
st.caption("Detailed IDS detection logs grouped by session")

# ================= SEARCH / FILTER =================
search_query = st.text_input(
    "🔍 Search sessions (by session number or timestamp)",
    placeholder="e.g. Session 3 or 2026-02-05"
)

# ================= LOAD SESSIONS =================
sessions, user_path = list_sessions(user_email)
sessions = sorted(sessions, key=lambda x: x["timestamp"], reverse=True)

# ================= FILTER LOGIC =================
if search_query:
    search_query = search_query.lower()
    sessions = [
        s for s in sessions
        if search_query in f"session {s['session_no']}".lower()
        or search_query in s["timestamp"].lower()
    ]

# ================= EMPTY STATE =================
if not sessions:
    st.info("No sessions match your search.")
    st.stop()

# ================= CSS =================
st.markdown("""
<style>
.session-row {
    background: white;
    border-radius: 16px;
    padding: 18px 22px;
    margin-bottom: 14px;
    box-shadow: 0 8px 22px rgba(0,0,0,0.08);
    border-left: 6px solid #6366f1;
}

.session-header {
    font-size: 13px;
    font-weight: 600;
    color: #64748b;
    margin-bottom: 6px;
}
</style>
""", unsafe_allow_html=True)

# ================= HEADER ROW =================
h1, h2, h3, h4 = st.columns([1.2, 3, 1.2, 1.2])
with h1: st.markdown("<div class='session-header'>Session</div>", unsafe_allow_html=True)
with h2: st.markdown("<div class='session-header'>Timestamp</div>", unsafe_allow_html=True)
with h3: st.markdown("<div class='session-header'>Download</div>", unsafe_allow_html=True)
with h4: st.markdown("<div class='session-header'>Delete</div>", unsafe_allow_html=True)

# ================= SESSION LIST =================
for s in sessions:
    st.markdown("<div class='session-row'>", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns([1.2, 3, 1.2, 1.2])

    with c1:
        if st.button(f"Session {s['session_no']}", key=f"view_{s['filename']}"):
            st.session_state.selected_session_file = os.path.join(
                user_path, s["filename"]
            )
            st.switch_page("pages/session_logs.py")

    with c2:
        st.write(s["timestamp"])

    with c3:
        with open(os.path.join(user_path, s["filename"]), "rb") as f:
            st.download_button(
                "Download",
                f,
                file_name=s["filename"],
                key=f"dl_{s['filename']}"
            )

    with c4:
        if st.button("Delete", key=f"del_{s['filename']}"):
            delete_session(user_email, s["filename"])
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
