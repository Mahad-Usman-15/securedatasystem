import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
import os

Data_file = "secure_data.json"
Salt = b"secure_salt_value"
Dur = 60

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "dur" not in st.session_state:
    st.session_state.dur = 0

def load_data():
    if os.path.exists(Data_file):
        with open(Data_file, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(Data_file, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), Salt, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), Salt, 100000).hex()

def encrypt(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None

stored_data = load_data()
st.title("🔐Secure Data Encryption")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation Menu", menu)

if choice == "Home":
    st.subheader("Welcome to Secure Data Encryption")

elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Enter your user name:")
    password = st.text_input("Enter your password", type="password")
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Warning: Username exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully")
        else:
            st.error("Both fields are required")

elif choice == "Login":
    st.subheader("Login")
    if time.time() < st.session_state.dur:
        remaining = int(st.session_state.dur - time.time())
        st.error(f"Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()
    username = st.text_input("Enter your username")
    password = st.text_input("Enter your password", type="password")
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome {username}")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error("Invalid credentials")
            if st.session_state.failed_attempts >= 3:
                st.session_state.dur = time.time() + Dur
                st.error("Too many failed attempts. Please try again later.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please log in first.")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")
        if st.button("Encrypt and save"):
            if data and passkey:
                encrypted = encrypt(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and saved successfully")
            else:
                st.error("All fields are required.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please log in first")
    else:
        st.subheader("Retrieve Data")
        userdata = stored_data.get(st.session_state.authenticated_user).get("data", [])

        if not userdata:
            st.info("No data found!")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(userdata):
                st.code(item, language="text")
            encrypted_text = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_text, passkey)
                if result:
                    st.success(f"Decrypted Text: {result}")
                else:
                    st.error("Incorrect passkey")
