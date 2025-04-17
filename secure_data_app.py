import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# -----------------------------
# Constants
# -----------------------------
KEY = Fernet.generate_key()  # You could persist this if you want consistent encryption
cipher = Fernet(KEY)
DATA_FILE = "data.json"

# -----------------------------
# Load and Save Functions
# -----------------------------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Load data at start
stored_data = load_data()

# -----------------------------
# Utility Functions
# -----------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# -----------------------------
# Session State Initialization
# -----------------------------
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True  # Default state unless locked out

# -----------------------------
# Streamlit UI
# -----------------------------
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# -----------------------------
# HOME PAGE
# -----------------------------
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("This app allows you to **securely store and retrieve** data using unique passkeys.")

# -----------------------------
# STORE DATA
# -----------------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    user_label = st.text_input("Enter a label to identify your data (e.g., secret1):")
    user_data = st.text_area("Enter data you want to encrypt:")
    passkey = st.text_input("Enter a passkey to protect it:", type="password")

    if st.button("Encrypt & Save"):
        if user_label and user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)

            stored_data[user_label] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data(stored_data)

            st.success("✅ Data encrypted and saved successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ All fields are required.")

# -----------------------------
# RETRIEVE DATA
# -----------------------------
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Encrypted Data")

    if not st.session_state.authorized:
        st.warning("🔒 Access blocked! Please login again from the Login page.")
    else:
        user_label = st.text_input("Enter the label for your data:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if user_label and passkey:
                if user_label in stored_data:
                    hashed_input = hash_passkey(passkey)
                    stored_entry = stored_data[user_label]

                    if stored_entry["passkey"] == hashed_input:
                        decrypted_text = decrypt_data(stored_entry["encrypted_text"])
                        st.success(f"✅ Decrypted Data: {decrypted_text}")
                        st.session_state.failed_attempts = 0
                    else:
                        st.session_state.failed_attempts += 1
                        st.error(f"❌ Incorrect passkey. Attempts left: {3 - st.session_state.failed_attempts}")

                        if st.session_state.failed_attempts >= 3:
                            st.session_state.authorized = False
                            st.warning("🚫 Too many failed attempts! Redirecting to Login.")
                else:
                    st.error("⚠️ No data found with this label.")
            else:
                st.error("⚠️ Please fill both fields.")

# -----------------------------
# LOGIN / RE-AUTHORIZATION
# -----------------------------
elif choice == "Login":
    st.subheader("🔐 Login to Reauthorize")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # In production, replace with secure method
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful! You are reauthorized.")
        else:
            st.error("❌ Incorrect master password.")
