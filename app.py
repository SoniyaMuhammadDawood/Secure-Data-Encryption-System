# app.py
import streamlit as st
import hashlib
import time
import os
import json
import base64
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# -------------------- Utility Functions --------------------
DATA_FILE = 'data.json'
LOCKOUT_TIME = 60  # seconds
MAX_ATTEMPTS = 3
SALT = b'streamlit_salt'

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# -------------------- Auth Functions --------------------
def register_user(username, password):
    data = load_data()
    if username in data:
        return False
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    data[username] = {'password': password_hash, 'storage': '', 'locked_until': 0}
    save_data(data)
    return True

def authenticate_user(username, password):
    data = load_data()
    if username not in data:
        return False
    if time.time() < data[username].get('locked_until', 0):
        return "locked"
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash == data[username]['password']:
        return True
    return False

def lockout_user(username):
    data = load_data()
    if username in data:
        data[username]['locked_until'] = time.time() + LOCKOUT_TIME
        save_data(data)

# -------------------- Encryption Functions --------------------
def derive_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000, dklen=32)
    return base64.urlsafe_b64encode(key)

def encrypt_data(key, plaintext):
    fernet = Fernet(key)
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt_data(key, ciphertext):
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext.encode()).decode()

# -------------------- Streamlit UI --------------------
st.set_page_config(page_title="Data Secure app", page_icon="🔏", layout="centered")

st.markdown(
    f"""
    <style>
    .stApp {{
        background: linear-gradient(to right, #fbc2eb, #a6c1ee);
    }}
    </style>
    """,
    unsafe_allow_html=True
)

def main():
    st.title("🔐 Secure Data Encryption System")
    data = load_data()

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ''
        st.session_state.attempts = 0

    if not st.session_state.logged_in:
        tab1, tab2 = st.tabs(["Login", "Register"])

        with tab2:
            new_user = st.text_input("Choose a username")
            new_pass = st.text_input("Choose a password", type="password")
            if st.button("Register"):
                if register_user(new_user, new_pass):
                    st.success("User registered. Please log in.")
                else:
                    st.error("Username already exists.")

        with tab1:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                auth = authenticate_user(username, password)
                if auth == True:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.attempts = 0
                    st.success("Logged in successfully!")
                elif auth == "locked":
                    st.error("Account locked. Try again later.")
                else:
                    st.session_state.attempts += 1
                    if st.session_state.attempts >= MAX_ATTEMPTS:
                        lockout_user(username)
                        st.error("Too many failed attempts. Account locked.")
                    else:
                        st.error("Incorrect credentials.")
    else:
        st.sidebar.success(f"Logged in as {st.session_state.username}")
        choice = st.sidebar.radio("Action", ["Store Data", "Retrieve Data", "Logout"])

        data = load_data()
        user = data[st.session_state.username]

        if choice == "Store Data":
            secret = st.text_area("Enter data to encrypt")
            passkey = st.text_input("Enter a passkey", type="password")
            if st.button("Encrypt and Store"):
                key = derive_key(passkey)
                encrypted = encrypt_data(key, secret)
                data[st.session_state.username]['storage'] = encrypted
                save_data(data)
                st.success("Data encrypted and saved.")

        elif choice == "Retrieve Data":
            passkey = st.text_input("Enter your passkey to decrypt", type="password")
            if st.button("Decrypt"):
                try:
                    key = derive_key(passkey)
                    decrypted = decrypt_data(key, user['storage'])
                    st.success("Decrypted Data:")
                    st.code(decrypted)
                except:
                    st.error("Incorrect passkey or data is empty.")

        elif choice == "Logout":
            st.session_state.logged_in = False
            st.session_state.username = ''
            st.session_state.attempts = 0
            st.rerun()


if __name__ == "__main__":
    main()

