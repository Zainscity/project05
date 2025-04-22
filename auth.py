# auth.py

import streamlit as st

# Hardcoded user login credentials
login_credentials = {
    "admin": "admin123"
}

def login_page():
    st.title("🔐 Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login_credentials.get(username) == password:
            st.session_state.login_user = username
            st.session_state.failed_attempts = 0
            st.success("Login successful!")
        else:
            st.error("Invalid credentials")
