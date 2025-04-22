import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ------------------- Setup -------------------
# Generate a Fernet key for encryption (would be static/secure in real use)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
stored_data = {}  # {"encrypted_text": {"encrypted_text": "...", "passkey": "..."}}
failed_attempts = 0

# ------------------- Utility Functions -------------------

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(plain_text, passkey):
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    entry = stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed_passkey:
        failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        failed_attempts += 1
        return None

# ------------------- Streamlit UI -------------------

st.set_page_config(page_title="Secure Data App", layout="centered")
st.title("🔐 Secure Data Encryption System")

# Sidebar Menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# ------------------- Pages -------------------

if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Securely store and retrieve your data using encrypted passkeys.")

elif choice == "Store Data":
    st.subheader("📦 Store Encrypted Data")
    data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(data, passkey)
            stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and saved!")
            st.code(encrypted)
        else:
            st.error("⚠️ Please enter both data and a passkey.")

elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Data")
    encrypted_input = st.text_area("Paste the encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if failed_attempts >= 3:
        st.warning("🔐 Too many failed attempts. Redirecting to Login page...")
        st.experimental_rerun()

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Data decrypted successfully:")
                st.code(result)
            else:
                attempts_left = max(0, 3 - failed_attempts)
                st.error(f"❌ Incorrect passkey. Attempts remaining: {attempts_left}")
        else:
            st.error("⚠️ Please provide both fields.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    master_key = st.text_input("Enter master password:", type="password")

    if st.button("Reauthorize"):
        if master_key == "admin123":  # Hardcoded for demo
            failed_attempts = 0
            st.success("🔓 Access restored. Try retrieving your data again.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
