import streamlit as st

def require_login():
    if "logged_in" not in st.session_state or not st.session_state.logged_in:
        st.error("Please login first")
        st.stop()

def require_role(role):
    if st.session_state.role != role:
        st.error("Access denied")
        st.stop()

