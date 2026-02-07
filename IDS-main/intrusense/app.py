import streamlit as st
import streamlit.components.v1 as components

# ✅ MUST BE FIRST STREAMLIT COMMAND
st.set_page_config(
    page_title="IDS Web App",
    layout="wide",
    page_icon="🛡️"
)

# ---------------- SESSION STATE ----------------
if "page" not in st.session_state:
    st.session_state.page = "welcome"

if "started" not in st.session_state:
    st.session_state.started = False

if "show_sidebar" not in st.session_state:
    st.session_state.show_sidebar = True

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.email = None


from database import create_users_table
from auth import register_user, login_user

# ---------------- UI STYLING ----------------
st.markdown("""
<style>
/* =========================================================
   GLOBAL RESET & BACKGROUND
   ========================================================= */
header {
    visibility: visible !important;
}

.block-container {
    padding-top: 0rem;
}

/* ===== FORCE LOGIN INPUT WIDTH ===== */
.login-wrapper {
    max-width: 420px;
    margin: 0 auto;
}

.login-wrapper .stTextInput,
.login-wrapper .stPassword,
.login-wrapper .stButton {
    width: 100% !important;
}

.login-wrapper input {
    max-width: 420px !important;
}


body {
    background-color: #020617;
}

/* =========================================================
   SIDEBAR
   ========================================================= */
[data-testid="stSidebar"] {
    background-color: #ffffff;
}

[data-testid="stSidebar"] * {
    color: #000000 !important;
}

/* =========================================================
   LOGIN / REGISTER FORM
   ========================================================= */
label {
    font-size: 17px !important;
    font-weight: 600 !important;
    color: #EAF6FF !important;
}

input {
    font-size: 16px !important;
}

input::placeholder {
    font-size: 15px;
    color: #9fb3c8;
}

div[data-baseweb="input"] > div {
    min-height: 46px;
}

/* Tabs */
button[data-baseweb="tab"] {
    color: #EAF6FF !important;
    font-weight: 600;
    font-size: 16px;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #00e5ff !important;
    text-shadow: 0 0 8px rgba(0,229,255,0.9);
}

/* Tagline under login title */
.login-tagline {
    font-size: 19px;
    font-weight: 500;
    color: #cfe8f3;
    letter-spacing: 0.6px;
    margin-bottom: 45px;
    text-align: center;
}


/* =========================================================
   BUTTONS (ONLY FOR LOGIN / NAVIGATION)
   ========================================================= */
.stButton > button {
    border-radius: 14px;
    font-size: 16px;
    font-weight: 600;
    padding: 10px 14px;
}
.hero-left {
    padding-left: 60px;
}
/* ===== MAIN LAYOUT (65 / 35) ===== */
.main-layout {
    display: flex;
    height: calc(100vh - 5rem);
    padding: 3rem 4rem;
    gap: 3rem;
}

.left-hero {
    flex: 0 0 65%;
    display: flex;
    flex-direction: column;
    justify-content: center;
}

.right-actions {
    flex: 0 0 35%;
    display: flex;
    flex-direction: column;
    justify-content: center;
}

/* ===== STREAMLIT TOP NAVBAR ===== */
header[data-testid="stHeader"] {
    background: #020617;
    border-bottom: 1px solid rgba(255,255,255,0.08);
}

header[data-testid="stHeader"] * {
    color: #ffffff !important;
}

/* ===== HERO-MATCHED CTA CARDS ===== */
.cta-card {
    border-radius: 32px;
    padding: 44px;
    margin-bottom: 36px;
    color: #e6f6ff;
    cursor: pointer;

    /* Glass + dark cyber base */
    background: rgba(2, 6, 23, 0.65);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);

    /* Subtle neon border */
    border: 1px solid rgba(56, 189, 248, 0.25);

    /* Soft glow like hero */
    box-shadow:
        0 20px 50px rgba(0, 0, 0, 0.6),
        inset 0 0 40px rgba(56, 189, 248, 0.08);

    transition: all 0.35s ease;
}

.cta-card:hover {
    transform: translateY(-10px) scale(1.02);

    box-shadow:
        0 30px 70px rgba(0, 0, 0, 0.7),
        inset 0 0 60px rgba(56, 189, 248, 0.18);
}

/* Detection Card Accent */
.cta-detection {
    border-left: 4px solid rgba(56, 189, 248, 0.9);
}

/* User Dashboard Card Accent */
.cta-dashboard {
    border-left: 4px solid rgba(30, 222, 72, 0.9);
}

/* Card text */
.cta-card h3 {
    font-size: 30px;
    font-weight: 800;
    margin-bottom: 12px;
    color: #ffffff;
    letter-spacing: 0.5px;
}

.cta-card p {
    font-size: 16px;
    opacity: 0.9;
    line-height: 1.6;
}

.cta-card::after {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 32px;
    pointer-events: none;
    box-shadow: inset 0 0 80px rgba(30, 222, 72, 0.05);
}

</style>
""", unsafe_allow_html=True)



create_users_table()

# ---------------- LOGIN PAGE ----------------
# ---------------- LOGIN PAGE ----------------
import base64

def get_bg(image_path):
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode()

if not st.session_state.logged_in:
    bg = get_bg("green_bg.jpg")

    st.markdown(f"""
    <style>
    [data-testid="stAppViewContainer"] {{
        background: url("data:image/jpg;base64,{bg}") no-repeat center center fixed;
        background-size: cover;
    }}
    </style>
    """, unsafe_allow_html=True)




    _, center, _ = st.columns([3, 2, 3])  # controls width

    with center:
        st.markdown("""
        <h1 style="
            text-align: center;
            color: #EAF6FF;
            font-size: 42px;
            font-weight: 800;
            text-shadow: 0 0 12px rgba(0,180,255,0.6);
            margin-top: 60px;
        ">
                INTRUSENSE
        </h1>

        <div style="
            text-align:center;
            font-size:19px;
            color:#cfe8f3;
            margin-bottom:40px;
        ">
            Detect • Analyze • Protect
        </div>
        """, unsafe_allow_html=True)

        tab1, tab2 = st.tabs(["Login", "Register"])

        with tab1:
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")

            if st.button("Login", use_container_width=True):
                result = login_user(email, password)

                if result == "admin" or result == "user":
                    st.session_state.logged_in = True
                    st.session_state.email = email
                    st.session_state.role = result
                    st.session_state.page = "welcome"
                    st.rerun()

                elif result == "blocked":
                    st.error("Your account has been blocked by admin")

                elif result == "not_found":
                    st.error("User not found")

                else:
                    st.error("Invalid credentials")

        with tab2:
            r_email = st.text_input("User Email")
            r_password = st.text_input("User Password", type="password")

            if st.button("Register", use_container_width=True):
                if register_user(r_email, r_password):
                    st.success("Registered successfully. Please login.")
                else:
                    st.error("Email already exists")


# ---------------- AFTER LOGIN ----------------
else:
    st.markdown("""
    <style>
    /* ===== DASHBOARD BACKGROUND ===== */
    [data-testid="stAppViewContainer"] {
        background: linear-gradient(135deg, #020617, #02040f);
    }
    </style>
    """, unsafe_allow_html=True)


    # ----- SIDEBAR -----
    if st.session_state.show_sidebar:
        st.sidebar.markdown("## 👤 User Info")
        st.sidebar.success(f"**Email:**\n{st.session_state.email}")
        st.sidebar.info(f"**Role:** {st.session_state.role.upper()}")
        st.sidebar.markdown("---")

        if st.session_state.role == "admin":
            if st.sidebar.button("Admin Dashboard"):
                st.switch_page("pages/admin_dashboard.py")

        if st.sidebar.button("Logout"):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()

    # 🔙 BACK BUTTON
    if st.session_state.page != "welcome":
        if st.button("⬅ Back"):
            st.session_state.page = "welcome"
            st.session_state.started = False
            st.rerun()

    # ---------------- WELCOME PAGE ----------------
    if st.session_state.page == "welcome":


        container = st.container()

        with container:
            left, right = st.columns([0.65, 0.35], gap="large")

        # -------- LEFT HERO --------
            with left:
                components.html(
                    """
                    <div id="hero-wrapper">
                        <div id="hero-vanta"></div>

                        <div class="hero-text">
                            <h1>Welcome to INTRUSENSE</h1>
                            <p>
                                Secure your network, detect intrusions in real time,
                                and analyze threats using intelligent detection models
                                designed for modern cyber environments.
                            </p>
                        </div>
                    </div>

                    <style>
                    #hero-wrapper {
                        position: relative;
                        width: 100%;
                        height: 800px;
                        border-radius: 42px;
                        overflow: hidden;
                        margin-top: 5rem;
                    }

                    #hero-vanta {
                        position: absolute;
                        top: 0;
                        left: 0;
                        width: 100%;
                        height: 100%;
                    }

                    .hero-text {
                        position: absolute;
                        inset: 0;
                        z-index: 2;

                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;

                        text-align: center;
                        padding: 0 4rem;
                    }
                    #hero-wrapper::after {
                        content: "";
                        position: absolute;
                        inset: 0;
                        border-radius: 42px;
                        box-shadow: inset 0 0 80px rgba(56,189,248,0.15);
                        pointer-events: none;
                    }

                    .hero-text h1 {
                        font-size: 68px;
                        font-weight: 800;
                        font-family: "Poppins", "Segoe UI", sans-serif;
                        margin-bottom: 24px;
                        color: #ffffff;
                        letter-spacing: 1px;
                        text-shadow: 0 0 16px rgba(255,255,255,0.25);
                    }
                    .hero-text p {
                        font-size: 24px;
                        font-style: italic;
                        color: #e6f6ff;
                        max-width: 820px;
                        line-height: 1.6;
                    }

                    </style>

                    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>

                    <script>
                    VANTA.NET({
                        el: "#hero-vanta",
                        mouseControls: true,
                        touchControls: true,
                        gyroControls: false,
                        color: 0x1ede48,
                        backgroundColor: 0x020617,
                        points: 12,
                        maxDistance: 22,
                        spacing: 18
                    });
                    </script>
                    """,
                    height=1200
                )


            # -------- RIGHT ACTIONS --------
            with right:
                st.markdown("<div style='height: 10rem'></div>", unsafe_allow_html=True)

                st.markdown("""
                <div class="cta-card cta-detection">
                    <h3>Detection Page</h3>
                    <p>Upload traffic data and detect network attacks</p>
                </div>
                """, unsafe_allow_html=True)

                if st.button("Open Detection Page", use_container_width=True):
                    st.switch_page("pages/detection_page.py")

                st.markdown("""
                <div class="cta-card cta-dashboard">
                    <h3>User Dashboard</h3>
                    <p>View reports, history, and attack analysis</p>
                </div>
                """, unsafe_allow_html=True)

                if st.button("Open User Dashboard", use_container_width=True):
                    st.switch_page("pages/user_dashboard.py")


