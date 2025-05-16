import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet # pip install streamlit cryptography / pip install cryptography
import base64
import hashlib
import datetime

# Constants
DATA_FILE = "secure_data.json"
SALT = b'streamlit_salt'
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 60  # seconds

# Load or initialize data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {"users": {}}

# Save data
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=4)

# Hashing passkey with PBKDF2
def hash_passkey(passkey):
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return base64.b64encode(key).decode()

# Generate encryption key for Fernet
def generate_key():
    return Fernet.generate_key()

# Encrypt & Decrypt functions
def encrypt_text(text, fernet_key):
    return Fernet(fernet_key).encrypt(text.encode()).decode()

def decrypt_text(cipher, fernet_key):
    return Fernet(fernet_key).decrypt(cipher.encode()).decode()

# Initialize session state
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = {}
if 'locked_out_until' not in st.session_state:
    st.session_state.locked_out_until = {}

# ---------------- Login System ----------------

def login_page():
    st.title("🔐 Login or Register")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if username in st.session_state.locked_out_until:
        if time.time() < st.session_state.locked_out_until[username]:
            remaining = int(st.session_state.locked_out_until[username] - time.time())
            st.warning(f"Account locked. Try again in {remaining} seconds.")
            return

    if st.button("Login / Register"):
        hashed = hash_passkey(password)

        if username in stored_data["users"]:
            if stored_data["users"][username]["password"] == hashed:
                st.success("Login successful!")
                st.session_state.current_user = username
                st.session_state.login_attempts[username] = 0
            else:
                st.session_state.login_attempts[username] = st.session_state.login_attempts.get(username, 0) + 1
                st.error(f"Wrong password. Attempt {st.session_state.login_attempts[username]}/{MAX_ATTEMPTS}")

                if st.session_state.login_attempts[username] >= MAX_ATTEMPTS:
                    st.session_state.locked_out_until[username] = time.time() + LOCKOUT_TIME
                    st.warning("Too many failed attempts. Account locked for 60 seconds.")
        else:
            # Register new user
            key = generate_key().decode()
            stored_data["users"][username] = {
                "password": hashed,
                "fernet_key": key,
                "entries": []
            }
            save_data()
            st.success("User registered. Please login again.")
            st.session_state.login_attempts[username] = 0

# ---------------- Data Store ----------------

def store_data():
    st.title("📝 Store Secure Data")

    data = st.text_area("Enter text to encrypt and store")
    if st.button("Store"):
        if data:
            user = st.session_state.current_user
            fernet_key = stored_data["users"][user]["fernet_key"]
            encrypted = encrypt_text(data, fernet_key.encode())
            stored_data["users"][user]["entries"].append({
                "encrypted_text": encrypted,
                "timestamp": datetime.datetime.now().isoformat()
            })
            save_data()
            st.success("Data stored securely!")
        else:
            st.warning("Text cannot be empty.")

    if st.button("🔙 Back to Home"):
        st.session_state.page = "home"

# ---------------- Data Retrieve ----------------

def retrieve_data():
    st.title("🔍 Retrieve Your Data")

    user = st.session_state.current_user
    entries = stored_data["users"][user]["entries"]
    if entries:
        for i, entry in enumerate(entries[::-1], start=1):
            with st.expander(f"📄 Entry {i} — {entry['timestamp']}"):
                try:
                    decrypted = decrypt_text(entry["encrypted_text"], stored_data["users"][user]["fernet_key"].encode())
                    st.code(decrypted)
                except Exception as e:
                    st.error("Failed to decrypt.")
    else:
        st.info("No data stored yet.")

    if st.button("🔙 Back to Home"):
        st.session_state.page = "home"

# ---------------- Main App ----------------

def main():
    if st.session_state.current_user is None:
        login_page()
        return

    if "page" not in st.session_state:
        st.session_state.page = "home"

    if st.session_state.page == "home":
        st.title(f"Welcome, {st.session_state.current_user} 👋")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("➕ Store Data"):
                st.session_state.page = "store"
        with col2:
            if st.button("🔓 Retrieve Data"):
                st.session_state.page = "retrieve"
        if st.button("🚪 Logout"):
            st.session_state.current_user = None
            st.session_state.page = "home"
    elif st.session_state.page == "store":
        store_data()
    elif st.session_state.page == "retrieve":
        retrieve_data()

if __name__ == "__main__":
    main()



# streamlit run app.py