import streamlit as st

def render_user_sidebar():
    st.sidebar.markdown("## 👤 User Information")

    st.sidebar.success(f"**Email:** {st.session_state.email}")
    st.sidebar.info(f"**Role:** {st.session_state.role.upper()}")

    st.sidebar.markdown("---")

    if st.sidebar.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.switch_page("app.py")
