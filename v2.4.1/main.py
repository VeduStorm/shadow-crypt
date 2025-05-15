#v2.4.1
# Imports
import base64
import hashlib
import json
import os
import platform
import socket
import secrets
import smtplib
import sys
import pyotp
import qrcode
from PySide6.QtGui import QPixmap
import tempfile
import uuid
from datetime import datetime
from datetime import timedelta
from email.mime.text import MIMEText
import firebase_admin
import hkdf
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox, QDialog, QFrame, QTabWidget,
    QComboBox, QRadioButton, QButtonGroup, QPlainTextEdit, QTextEdit,
    QFileDialog
)
from cryptography.fernet import Fernet, InvalidToken
from firebase_admin import credentials, firestore

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

#Initialize Firebase
Key=b'kAPPYqoyQir0s88_Ay-8rkcXQvund2ugBK5r5Ya07Og='
f = Fernet(Key)
encrypted_file_path = 'data/serviceAccountKey.enc'
if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError("Encrypted service account key file not found")
with open(encrypted_file_path, "rb") as file:
    file = file.read()
    try:
        decrypted_data = f.decrypt(file)
        temp_file = os.path.join(tempfile.gettempdir(), "serviceAccountKey.json")
        with open(temp_file, "wb") as f:
            f.write(decrypted_data)
    except Exception as e:
        raise Exception(f"Failed to decrypt service account key: {str(e)}")

cred = credentials.Certificate(temp_file)
firebase_admin.initialize_app(cred)
db = firestore.client()

SYSTEM_ID_PATH = os.path.join(tempfile.gettempdir(), "system_id.txt")

def get_system_id():
    if os.path.exists(SYSTEM_ID_PATH):
        with open(SYSTEM_ID_PATH, "r") as f:
            return f.read().strip()
    else:
        system_info = f"{platform.node()}-{platform.system()}-{platform.processor()}"
        system_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, system_info))
        with open(SYSTEM_ID_PATH, "w") as f:
            f.write(system_id)
        return system_id

SYSTEM_ID = get_system_id()

SESSION_FILE_PATH = resource_path("data/sessionid.enc")


def save_session(username):
    """Save an encrypted session file and store secret_key in Firestore, invalidating other sessions."""
    try:
        # Delete existing sessions for this user
        reset_all_user_sessions(username)

        current_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        secret_key = secrets.token_hex(16)
        session_data = f"{current_time}:{SYSTEM_ID}:{username}:{secret_key}"
        encrypted_data = fernet.encrypt(session_data.encode())
        with open(SESSION_FILE_PATH, "wb") as f:
            f.write(encrypted_data)

        # Store secret_key in Firestore
        session_id = str(uuid.uuid4())
        db.collection("sessions").document(session_id).set({
            "username": username,
            "secret_key": secret_key,
            "created_at": current_time,
            "system_id": SYSTEM_ID
        })
        log_activity(username, f"Session created with ID: {session_id}")
        return session_id
    except Exception as e:
        log_activity(username, f"Failed to save session: {str(e)}")
        return None


def validate_session():
    """Validate session file and secret_key against Firestore."""
    if not os.path.exists(SESSION_FILE_PATH):
        return None
    try:
        with open(SESSION_FILE_PATH, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        parts = decrypted_data.split(":")
        if len(parts) != 4:
            log_activity("unknown", "Session validation failed: Invalid data format")
            return None
        session_datetime_str = parts[0]
        session_system_id = parts[1]
        session_username = parts[2]
        session_secret_key = parts[3]

        # Parse session datetime
        session_datetime = datetime.strptime(session_datetime_str, "%d-%m-%Y_%H-%M-%S")

        # Check if session is within 30 days
        if (datetime.now() - session_datetime).days > 30:
            log_activity(session_username, "Session expired")
            return None
        # Check if system ID matches
        if session_system_id != SYSTEM_ID:
            log_activity(session_username, "Session invalid: System ID mismatch")
            return None
        # Verify secret_key in Firestore
        sessions = db.collection("sessions").where("username", "==", session_username).where("secret_key", "==",
                                                                                             session_secret_key).where(
            "system_id", "==", SYSTEM_ID).get()
        if not sessions:
            log_activity(session_username, "Session invalid: Secret key mismatch or overwritten by another machine")
            return None

        log_activity(session_username, "Session validated successfully")
        return session_username
    except (InvalidToken, ValueError, Exception) as e:
        log_activity("unknown", f"Session validation failed: {str(e)}")
        return None

def reset_session():
    """Reset the session by deleting the session file and Firestore record."""
    try:
        if os.path.exists(SESSION_FILE_PATH):
            with open(SESSION_FILE_PATH, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data).decode()
            parts = decrypted_data.split(":")
            if len(parts) == 4:
                session_username = parts[2]
                session_secret_key = parts[3]
                sessions = db.collection("sessions").where("username", "==", session_username).where("secret_key", "==", session_secret_key).get()
                for session in sessions:
                    db.collection("sessions").document(session.id).delete()
            os.remove(SESSION_FILE_PATH)
            log_activity("unknown", "Session reset")
    except Exception as e:
        log_activity("unknown", f"Failed to reset session: {str(e)}")

def reset_all_user_sessions(username):
    """Reset all sessions for a user by deleting Firestore records and local session file if applicable."""
    try:
        # Delete all Firestore session records for the user
        sessions = db.collection("sessions").where("username", "==", username).get()
        for session in sessions:
            db.collection("sessions").document(session.id).delete()
            log_activity(username, f"Session {session.id} deleted due to password change or new login")

        # Check and delete local session file if it belongs to the user
        if os.path.exists(SESSION_FILE_PATH):
            with open(SESSION_FILE_PATH, "rb") as f:
                encrypted_data = f.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data).decode()
                parts = decrypted_data.split(":")
                if len(parts) == 4 and parts[2] == username:
                    os.remove(SESSION_FILE_PATH)
                    log_activity(username, "Local session file deleted due to password change or new login")
            except (InvalidToken, ValueError, Exception) as e:
                log_activity(username, f"Failed to process local session file: {str(e)}")
    except Exception as e:
        log_activity(username, f"Failed to reset all sessions: {str(e)}")

def hash_password(password):
    h = hashlib.new('SHA256')
    h.update(password.encode())
    password = h.hexdigest()
    h.update(password.encode())
    return h.hexdigest()

# Initialize Firestore configuration if it doesn't exist
def initialize_config():
    config_ref = db.collection("config").document("app_config")
    config = config_ref.get()
    if not config.exists:
        new_key = Fernet.generate_key().decode()
        config_data = {
            "KEY": new_key,
            "EMAIL_ADDRESS": "dev.team751@gmail.com",
            "EMAIL_PASSWORD": "onujvrgnjbghjyko"
        }
        config_ref.set(config_data)
    return config_ref.get().to_dict()

# Load configuration from Firestore
config = initialize_config()
KEY = config.get("KEY")
EMAIL_ADDRESS = config.get("EMAIL_ADDRESS")
EMAIL_PASSWORD = config.get("EMAIL_PASSWORD")

if KEY is None:
    print("Error: 'KEY' not found in Firestore config.")
    sys.exit(1)

try:
    KEY = KEY.encode()
    fernet = Fernet(KEY)
except (ValueError, InvalidToken):
    print("Error: Invalid Fernet key in Firestore config.")
    sys.exit(1)

# Dictionaries for encryption/decryption
A_MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
    'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
    'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    'a': '.-', 'b': '-...', 'c': '-.-.', 'd': '-..', 'e': '.', 'f': '..-.', 'g': '--.', 'h': '....',
    'i': '..', 'j': '.---', 'k': '-.-', 'l': '.-..', 'm': '--', 'n': '-.', 'o': '---', 'p': '.--.',
    'q': '--.-', 'r': '.-.', 's': '...', 't': '-', 'u': '..-', 'v': '...-', 'w': '.--', 'x': '-..-',
    'y': '-.--', 'z': '--..',
    '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '0': '-----', ', ': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.',
    '-': '-....-', '(': '-.--.', ')': '-.--.-', ' ': '      '
}
A_MORSE_CODE_REVERSED = {value: key for key, value in A_MORSE_CODE_DICT.items()}

A_BINARY_CODE_DICT = {
    'A': '01000001', 'B': '01000010', 'C': '01000011', 'D': '01000100', 'E': '01000101', 'F': '01000110',
    'G': '01000111', 'H': '01001000', 'I': '01001001', 'J': '01001010', 'K': '01001011', 'L': '01001100',
    'M': '01001101', 'N': '01001110', 'O': '01001111', 'P': '01010000', 'Q': '01010001', 'R': '01010010',
    'S': '01010011', 'T': '01010100', 'U': '01010101', 'V': '01010110', 'W': '01010111', 'X': '01011000',
    'Y': '01011001', 'Z': '01011010',
    'a': '01100001', 'b': '01100010', 'c': '01100011', 'd': '01100100', 'e': '01100101', 'f': '01100110',
    'g': '01100111', 'h': '01101000', 'i': '01101001', 'j': '01101010', 'k': '01101011', 'l': '01101100',
    'm': '01101101', 'n': '01101110', 'o': '01101111', 'p': '01110000', 'q': '01110001', 'r': '01110010',
    's': '01110011', 't': '01110100', 'u': '01110101', 'v': '01110110', 'w': '01110111', 'x': '01111000',
    'y': '01111001', 'z': '01111010',
    '1': '00110001', '2': '00110010', '3': '00110011', '4': '00110100', '5': '00110101', '6': '00110110',
    '7': '00110111', '8': '00111000', '9': '00111001', '0': '00110000', ',': '00111001', '.': '00101110',
    '?': '00111111', '/': '00101111', '-': '00101101', '(': '00101000', ')': '00101001', ' ': '00100000',
    ':': '00111010', '@': '01000000', '!': '00100001'
}
A_BINARY_CODE_REVERSED = {value: key for key, value in A_BINARY_CODE_DICT.items()}

S_MORSE_CODE_DICT = {
    'V': '.-', 'E': '-...', 'D': '-.-.', 'A': '-..', 'N': '.', 'T': '..-.', 'B': '--.', 'C': '....',
    'F': '..', 'G': '.---', 'H': '-.-', 'I': '.-..', 'K': '--', 'J': '-.', 'L': '---', 'P': '.--.',
    'Q': '--.-', 'R': '.-.', 'S': '...', 'O': '-', 'U': '..-', 'M': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    'v': '.-', 'e': '-...', 'd': '-.-.', 'a': '-..', 'n': '.', 't': '..-.', 'b': '--.', 'c': '....',
    'f': '..', 'g': '.---', 'h': '-.-', 'i': '.-..', 'k': '--', 'j': '-.', 'l': '---', 'p': '.--.',
    'q': '--.-', 'r': '.-.', 's': '...', 'o': '-', 'u': '..-', 'm': '...-', 'w': '.--', 'x': '-..-',
    'y': '-.--', 'z': '--..',
    '4': '.----', '8': '..---', '9': '...--', '2': '....-', '3': '.....', '6': '-....', '7': '--...',
    '1': '---..', '5': '----.', '0': '-----', ', ': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.',
    '-': '-....-', '(': '-.--.', ')': '-.--.-', ' ': '      '
}
S_MORSE_CODE_REVERSED = {value: key for key, value in S_MORSE_CODE_DICT.items()}

S_BINARY_CODE_DICT = {
    'V': '01000001', 'E': '01000010', 'D': '01000011', 'A': '01000100', 'N': '01000101', 'T': '01000110',
    'B': '01000111', 'C': '01001000', 'F': '01001001', 'G': '01001010', 'H': '01001011', 'I': '01001100',
    'M': '01001101', 'J': '01001110', 'K': '01001111', 'L': '01010000', 'O': '01010001', 'R': '01010010',
    'S': '01010011', 'P': '01010100', 'U': '01010101', 'Q': '01010110', 'W': '01010111', 'X': '01011000',
    'Y': '01011001', 'Z': '01011010',
    'v': '01100001', 'e': '01100010', 'd': '01100011', 'a': '01100100', 'n': '01100101', 't': '01100110',
    'b': '01100111', 'c': '01101000', 'f': '01101001', 'g': '01101010', 'h': '01101011', 'i': '01101100',
    'm': '01101101', 'j': '01101110', 'k': '01101111', 'l': '01110000', 'o': '01110001', 'r': '01110010',
    's': '01110011', 'p': '01110100', 'u': '01110101', 'q': '01110110', 'w': '01110111', 'x': '01111000',
    'y': '01111001', 'z': '01111010',
    '5': '00110001', '4': '00110010', '3': '00110011', '1': '00110100', '8': '00110101', '6': '00110110',
    '7': '00110111', '2': '00111000', '9': '00111001', '0': '00110000', ',': '00111001', '.': '00101110',
    '?': '00111111', '/': '00101111', '-': '00101101', '(': '00101000', ')': '00101001', ' ': '00100000',
    ':': '00111010', '@': '01000000', '!': '00100001'
}
S_BINARY_CODE_REVERSED = {value: key for key, value in S_BINARY_CODE_DICT.items()}

def load_log_file():
    try:
        logs_ref = db.collection("logs").document("initial")
        logs = logs_ref.get()
        if not logs.exists:
            return {}
        decrypted_data = fernet.decrypt(logs.to_dict().get("data").encode()).decode()
        return json.loads(decrypted_data)
    except (json.JSONDecodeError, ValueError, InvalidToken):
        return {}

def save_auth_file(data):
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    db.collection("auth").document("users").set({"data": encrypted_data.decode()})

def save_log_file(data):
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    db.collection("logs").document("initial").set({"data": encrypted_data.decode()})

def log_activity(username, activity):
    """Log user activity to Firestore with a limit of 20 entries per user."""
    try:
        logs = load_log_file()
        if username not in logs:
            logs[username] = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logs[username].append({"timestamp": timestamp, "activity": activity})
        if len(logs[username]) > 20:
            logs[username] = logs[username][-20:]  # Keep newest 20 logs
        save_log_file(logs)
    except Exception as e:
        print(f"Error logging activity: {e}")

def save_custom_dictionary(username, dict_name, binary_dict, morse_dict):
    try:
        dict_data = {
            "binary": binary_dict,
            "morse": morse_dict,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username
        }
        encrypted_data = fernet.encrypt(json.dumps(dict_data).encode()).decode()
        db.collection("custom_dictionaries").document(dict_name).set({"data": encrypted_data})
        log_activity(username, "create_custom_dictionary", dict_name, f"Created custom dictionary: {dict_name}")
    except Exception as e:
        print(f"Error saving custom dictionary: {e}")

def load_custom_dictionary(dict_name):
    try:
        doc = db.collection("custom_dictionaries").document(dict_name).get()
        if not doc.exists:
            return None
        decrypted_data = fernet.decrypt(doc.to_dict().get("data").encode()).decode()
        return json.loads(decrypted_data)
    except Exception as e:
        print(f"Error loading custom dictionary: {e}")
        return None

def generate_2fa_secret():
    return pyotp.random_base32()

def save_2fa_secret(username, secret):
    try:
        if not secret or len(secret) < 16:  # Validate base32 secret
            log_activity(username, "Failed to save 2FA secret: Invalid secret format")
            return
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == username), None)
        if user:
            try:
                user["2fa_secret"] = fernet.encrypt(secret.encode()).decode()
                user["2fa_enabled"] = True
                save_auth_file(auth_data)
                log_activity(username, "enable_2fa", username, "Enabled 2FA")
            except Exception as e:
                log_activity(username, f"Failed to save 2FA secret: Encryption error - {str(e)}")
        else:
            log_activity(username, "Failed to save 2FA secret: User not found")
    except Exception as e:
        log_activity(username, f"Failed to save 2FA secret: Unexpected error - {str(e)}")

def disable_2fa(username):
    try:
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == username), None)
        if user:
            user["2fa_secret"] = ""
            user["2fa_enabled"] = False
            save_auth_file(auth_data)
            log_activity(username, "disable_2fa", username, "Disabled 2FA")
    except Exception as e:
        print(f"Error disabling 2FA: {e}")

def verify_2fa_code(username, code):
    try:
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == username), None)
        if not user or not user.get("2fa_enabled", False):
            log_activity(username, "2FA verification failed: 2FA not enabled or user not found")
            return False
        if not user.get("2fa_secret"):
            log_activity(username, "2FA verification failed: No 2FA secret stored")
            return False
        try:
            secret = fernet.decrypt(user["2fa_secret"].encode()).decode()
            if not secret or len(secret) < 16:  # Basic validation for base32 secret
                log_activity(username, "2FA verification failed: Invalid 2FA secret format")
                return False
        except Exception as e:
            log_activity(username, f"2FA verification failed: Decryption error - {str(e)}")
            return False
        totp = pyotp.TOTP(secret, interval=30)
        verified = totp.verify(code, valid_window=1)  # Allow 30s drift
        if not verified:
            log_activity(username, "2FA verification failed: Invalid TOTP code")
        return verified
    except Exception as e:
        log_activity(username, f"2FA verification failed: Unexpected error - {str(e)}")
        return False

def load_auth_file():
            try:
                auth_ref = db.collection("auth").document("users")
                auth = auth_ref.get()
                if not auth.exists:
                    return {"users": []}
                decrypted_data = fernet.decrypt(auth.to_dict().get("data").encode()).decode()
                return json.loads(decrypted_data)
            except (json.JSONDecodeError, ValueError, InvalidToken):
                return {"users": []}

def initialize_local_files():
    auth_ref = db.collection("auth").document("users")
    auth = auth_ref.get()
    if not auth.exists:
        initial_data = {"users": []}
        encrypted_data = fernet.encrypt(json.dumps(initial_data).encode())
        auth_ref.set({"data": encrypted_data.decode()})
    else:
        # Validate and clean up existing data
        auth_data = load_auth_file()
        valid_users = [u for u in auth_data.get("users", []) if "user" in u and "email" in u and "pass" in u]
        if len(valid_users) < len(auth_data.get("users", [])):
            log_activity("system", "Cleaned up invalid user entries in auth data")
            auth_data["users"] = valid_users
            save_auth_file(auth_data)

    logs_ref = db.collection("logs").document("initial")
    logs = logs_ref.get()
    if not logs.exists:
        initial_data = {}
        encrypted_data = fernet.encrypt(json.dumps(initial_data).encode())
        logs_ref.set({"data": encrypted_data.decode()})

initialize_local_files()

# Light Theme Stylesheet
LIGHT_STYLESHEET = """
* {
    font-family: 'Georgia', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #333333;
}

QMainWindow, QWidget {
    background-color: #f8f9fa;
}

QFrame#mainCard {
    background-color: white;
    border-radius: 12px;
    border: 1px solid #e0e0e0;
}

QTabWidget {
    background-color: white !important;
    border: none;
}

QTabWidget::pane {
    background-color: white !important;
    border: none;
    margin-top: 10px;
}

QTabBar {
    background-color: white !important;
    border: none;
    padding: 0px;
    margin: 0px;
    alignment: left;
    width: 100%;
}

QTabBar::tab {
    background-color: white !important;
    color: #666666;
    padding: 10px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 500;
    min-width: 100px;
    margin: 0px;
    spacing: 0px;
}

QTabBar::tab:selected {
    background-color: white !important;
    color: #4a90e2;
    border-bottom: 2px solid #4a90e2;
}

QTabBar::tab:hover {
    background-color: #f0f0f0 !important;
    color: #333333;
}

QTabBar::tab:!selected {
    background-color: white !important;
    color: #666666;
}

QTabBar::tab:disabled {
    background-color: white !important;
    color: #666666;
}

QLineEdit, QPlainTextEdit, QTextEdit {
    border: 1px solid #ced4da;
    border-radius: 6px;
    padding: 10px;
    font-size: 14px;
    background-color: white;
    selection-background-color: #4a90e2;
    selection-color: white;
}

QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border: 1px solid #4a90e2;
    outline: none;
}

QPlainTextEdit, QTextEdit {
    font-family: 'Georgia', 'Times New Roman', 'Courier New';
}

QTextEdit#logsText {
    font-family: 'Courier New', monospace;
    font-size: 13px;
    border: 1px solid #ced4da;
    border-radius: 6px;
    padding: 10px;
    background-color: #f8f9fa;
}

QPushButton {
    background-color: #4a90e2;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 12px 24px;
    font-size: 14px;
    font-weight: 500;
    min-width: 120px;
}

QPushButton:hover {
    background-color: #3a7bc8;
}

QPushButton:pressed {
    background-color: #2a6bb8;
}

QPushButton#secondary {
    background-color: transparent;
    color: #4a90e2;
    border: 1px solid #4a90e2;
}

QPushButton#secondary:hover {
    background-color: #f0f7ff;
}

QPushButton#secondary:pressed {
    background-color: #e0f0ff;
}

QPushButton:disabled {
    background-color: #cccccc;
    color: #666666;
    border: 1px solid #aaaaaa;
}

QLabel#titleLabel {
    font-size: 28px;
    font-weight: 600;
    color: #2c3e50;
}

QLabel#sectionLabel {
    font-size: 16px;
    font-weight: 500;
    color: #4a90e2;
    margin-bottom: 5px;
}

QLabel#subtitleLabel {
    font-size: 15px;
    color: #7f8c8d;
}

QRadioButton {
    spacing: 8px;
    font-size: 14px;
    color: #333333;
}

QComboBox {
    padding: 10px 15px;
    border: 2px solid #d1d5db;
    border-radius: 10px;
    background-color: #ffffff;
    color: #1f2937;
    font-size: 14px;
    font-weight: 500;
    outline: none;
}

QComboBox:hover {
    border-color: #4a90e2;
    background-color: #f9fafb;
}

QComboBox:focus {
    border-color: #4a90e2;
    background-color: #ffffff;
}

QComboBox::drop-down {
    border: none;
    width: 40px;
    background: transparent;
}

QComboBox::down-arrow {
    image: none;
    width: 16px;
    height: 16px;
    margin-right: 10px;
}

QComboBox QAbstractItemView {
    border: 2px solid #e5e7eb;
    border-radius: 8px;
    background-color: #ffffff;
    selection-background-color: #4a90e2;
    selection-color: #ffffff;
    padding: 5px;
    outline: none;
}

QComboBox QAbstractItemView::item {
    padding: 12px 15px;
    color: #1f2937;
    font-size: 14px;
    border-radius: 6px;
    min-height: 30px;
}

QComboBox QAbstractItemView::item:hover {
    background-color: #f0f7ff;
    color: #1f2937;
}

QComboBox QAbstractItemView::item:selected {
    background-color: #4a90e2;
    color: #ffffff;
}

Card {
    background-color: white;
    border-radius: 12px;
    border: none;
    padding: 30px;
}

Header {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #4a90e2, stop:1 #5ac8fa);
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    padding: 40px 20px;
}

QMessageBox {
    background-color: white;
}

QMessageBox QLabel {
    font-size: 15px;
}

QMessageBox QPushButton {
    min-width: 80px;
}

QPushButton#tableButton {
    padding: 5px 10px;
    font-size: 12px;
    min-width: 60px;
    border-radius: 4px;
}

QPushButton#tableButton:hover {
    background-color: #e0f0ff;
}

QPushButton#tableButton:pressed {
    background-color: #d0e0ff;
}

QPushButton#operationToggle {
    background-color: #4a90e2;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 14px;
    font-weight: 500;
}

QPushButton#operationToggle:hover {
    background-color: #3a7bc8;
}

QPushButton#operationToggle:pressed {
    background-color: #2a6bb8;
}
"""

# Dark Theme Stylesheet
DARK_STYLESHEET = """
* {
    font-family: 'Georgia', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #e5e7eb;
}

QMainWindow, QWidget {
    background-color: #1f2937;
}

QFrame#mainCard {
    background-color: #374151;
    border-radius: 12px;
    border: 1px solid #4b5563;
}

QTabWidget {
    background-color: #374151 !important;
    border: none;
}

QTabWidget::pane {
    background-color: #374151 !important;
    border: none;
    margin-top: 10px;
}

QTabBar {
    background-color: #374151 !important;
    border: none;
    padding: 0px;
    margin: 0px;
    alignment: left;
    width: 100%;
}

QTabBar::tab {
    background-color: #374151 !important;
    color: #9ca3af;
    padding: 10px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 500;
    min-width: 100px;
    margin: 0px;
    spacing: 0px;
}

QTabBar::tab:selected {
    background-color: #374151 !important;
    color: #4a90e2;
    border-bottom: 2px solid #4a90e2;
}

QTabBar::tab:hover {
    background-color: #4b5563 !important;
    color: #e5e7eb;
}

QTabBar::tab:!selected {
    background-color: #374151 !important;
    color: #9ca3af;
}

QTabBar::tab:disabled {
    background-color: #374151 !important;
    color: #9ca3af;
}

QLineEdit, QPlainTextEdit, QTextEdit {
    border: 1px solid #4b5563;
    border-radius: 6px;
    padding: 10px;
    font-size: 14px;
    background-color: #4b5563;
    color: #e5e7eb;
    selection-background-color: #4a90e2;
    selection-color: white;
}

QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border: 1px solid #4a90e2;
    outline: none;
}

QPlainTextEdit, QTextEdit {
    font-family: 'Georgia', 'Times New Roman', 'Courier New';
}

QTextEdit#logsText {
    font-family: 'Courier New', monospace;
    font-size: 13px;
    border: 1px solid #4b5563;
    border-radius: 6px;
    padding: 10px;
    background-color: #374151;
    color: #e5e7eb;
}

QPushButton {
    background-color: #4a90e2;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 12px 24px;
    font-size: 14px;
    font-weight: 500;
    min-width: 120px;
}

QPushButton:hover {
    background-color: #3a7bc8;
}

QPushButton:pressed {
    background-color: #2a6bb8;
}

QPushButton#secondary {
    background-color: transparent;
    color: #4a90e2;
    border: 1px solid #4a90e2;
}

QPushButton#secondary:hover {
    background-color: #4b5563;
}

QPushButton#secondary:pressed {
    background-color: #374151;
}

QPushButton:disabled {
    background-color: #6b7280;
    color: #9ca3af;
    border: 1px solid #4b5563;
}

QLabel#titleLabel {
    font-size: 28px;
    font-weight: 600;
    color: #e5e7eb;
}

QLabel#sectionLabel {
    font-size: 16px;
    font-weight: 500;
    color: #4a90e2;
    margin-bottom: 5px;
}

QLabel#subtitleLabel {
    font-size: 15px;
    color: #9ca3af;
}

QRadioButton {
    spacing: 8px;
    font-size: 14px;
    color: #e5e7eb;
}

QComboBox {
    padding: 10px 15px;
    border: 2px solid #4b5563;
    border-radius: 10px;
    background-color: #4b5563;
    color: #e5e7eb;
    font-size: 14px;
    font-weight: 500;
    outline: none;
}

QComboBox:hover {
    border-color: #4a90e2;
    background-color: #6b7280;
}

QComboBox:focus {
    border-color: #4a90e2;
    background-color: #4b5563;
}

QComboBox::drop-down {
    border: none;
    width: 40px;
    background: transparent;
}

QComboBox::down-arrow {
    image: none;
    width: 16px;
    height: 16px;
    margin-right: 10px;
}

QComboBox QAbstractItemView {
    border: 2px solid #4b5563;
    border-radius: 8px;
    background-color: #374151;
    selection-background-color: #4a90e2;
    selection-color: #ffffff;
    padding: 5px;
    outline: none;
}

QComboBox QAbstractItemView::item {
    padding: 12px 15px;
    color: #e5e7eb;
    font-size: 14px;
    border-radius: 6px;
    min-height: 30px;
}

QComboBox QAbstractItemView::item:hover {
    background-color: #4b5563;
    color: #e5e7eb;
}

QComboBox QAbstractItemView::item:selected {
    background-color: #4a90e2;
    color: #ffffff;
}

Card {
    background-color: #374151;
    border-radius: 12px;
    border: none;
    padding: 30px;
}

Header {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #4a90e2, stop:1 #5ac8fa);
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    padding: 40px 20px;
}

QMessageBox {
    background-color: #374151;
}

QMessageBox QLabel {
    font-size: 15px;
    color: #e5e7eb;
}

QMessageBox QPushButton {
    min-width: 80px;
}

QPushButton#tableButton {
    padding: 5px 10px;
    font-size: 12px;
    min-width: 60px;
    border-radius: 4px;
}

QPushButton#tableButton:hover {
    background-color: #4b5563;
}

QPushButton#tableButton:pressed {
    background-color: #374151;
}

QPushButton#operationToggle {
    background-color: #4a90e2;
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 14px;
    font-weight: 500;
}

QPushButton#operationToggle:hover {
    background-color: #3a7bc8;
}

QPushButton#operationToggle:pressed {
    background-color: #2a6bb8;
}
"""

class HeaderWidget(QWidget):
    def __init__(self, title, subtitle, parent=None):
        super().__init__(parent)
        self.setObjectName("Header")
        self.setFixedHeight(180)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 20)
        self.title = QLabel(title)
        self.title.setObjectName("titleLabel")
        self.title.setAlignment(Qt.AlignCenter)
        self.subtitle = QLabel(subtitle)
        self.subtitle.setObjectName("subtitleLabel")
        self.subtitle.setAlignment(Qt.AlignCenter)
        layout.addStretch()
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        layout.addStretch()

class CardWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)

class AuthApp(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.apply_theme("light")

    def apply_theme(self, theme):
        self.setStyleSheet(LIGHT_STYLESHEET if theme == "light" else DARK_STYLESHEET)

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowCrypt Login")
        self.setFixedSize(500, 600)

        # Check for valid session
        username = validate_session()
        if username:
            try:
                auth_data = load_auth_file()
                user = next((u for u in auth_data["users"] if u["user"] == username), None)
                if user and not user.get("locked", False):
                    log_activity(username, "Auto-login via session")
                    try:
                        self.main_window = ShadowCryptUI(username)
                        self.main_window.show()
                    except Exception as e:
                        log_activity(username, f"Auto-login error: {str(e)}")
                    log_activity(username, "Closing LoginWindow after auto-login")
                    self.hide()  # Hide the window immediately
                    self.deleteLater()  # Schedule for deletion
                    return
                else:
                    log_activity(username, "Auto-login failed: User locked or not found")
            except Exception as e:
                log_activity(username, f"Auto-login error: {str(e)}")

        self.setup_ui()
        self.apply_user_theme()

    def apply_user_theme(self):
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["role"] == "admin"), None)
        if user and "theme" in user:
            QApplication.instance().apply_theme(user["theme"])

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        header = HeaderWidget("Welcome Back", "Sign in to your account")
        main_layout.addWidget(header)

        card = CardWidget()
        form_layout = QVBoxLayout(card)
        form_layout.setContentsMargins(40, 30, 40, 30)
        form_layout.setSpacing(20)

        username_label = QLabel("Username:")
        username_label.setStyleSheet("font-weight: 500;")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)

        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-weight: 500;")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)

        self.login_btn = QPushButton("Sign In")
        self.login_btn.clicked.connect(self.validate_login)
        form_layout.addWidget(self.login_btn, 0, Qt.AlignCenter)

        actions_layout = QHBoxLayout()
        self.register_btn = QPushButton("Create Account")
        self.register_btn.setObjectName("secondary")
        self.register_btn.clicked.connect(self.show_registration)
        self.forgot_btn = QPushButton("Forgot Password?")
        self.forgot_btn.setObjectName("secondary")
        self.forgot_btn.clicked.connect(self.show_forgot_password)
        actions_layout.addWidget(self.register_btn)
        actions_layout.addWidget(self.forgot_btn)

        form_layout.addSpacing(15)
        form_layout.addLayout(actions_layout)

        main_layout.addWidget(card)
        main_layout.addStretch()

    def validate_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter both username and password.")
            return

        if username.lower() == "admin":
            log_activity(username, "Failed login attempt - admin not supported")
            QMessageBox.warning(self, "Error", "Admin not supported.")
            return

        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == username), None)

        if not user:
            log_activity(username, "Failed login attempt - user not found")
            QMessageBox.warning(self, "Error", "Invalid credentials.")
            return

        if user["pass"] != hash_password(password):
            log_activity(username, "Failed login attempt - incorrect password")
            QMessageBox.warning(self, "Error", "Invalid credentials.")
            return

        if user.get("locked", False):
            log_activity(username, "Failed login attempt - account locked")
            QMessageBox.warning(self, "Error", "Your account is locked. Contact support.")
            return

        if user.get("2fa_enabled", False):
            dialog = QDialog(self)
            dialog.setWindowTitle("2FA Verification")
            dialog.setFixedSize(300, 200)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(20, 20, 20, 20)

            label = QLabel("Enter the 6-digit code from Google Authenticator")
            otp_input = QLineEdit()
            otp_input.setPlaceholderText("6-digit code")
            otp_input.setMaxLength(6)
            verify_btn = QPushButton("Verify")
            layout.addWidget(label)
            layout.addWidget(otp_input)
            layout.addWidget(verify_btn, 0, Qt.AlignCenter)
            layout.addStretch()

            def verify_2fa():
                code = otp_input.text().strip()
                if not code or len(code) != 6 or not code.isdigit():
                    QMessageBox.warning(dialog, "Error", "Please enter a valid 6-digit code.")
                    return
                if verify_2fa_code(username, code):
                    dialog.accept()
                else:
                    log_activity(username, "Failed login attempt - invalid 2FA code")
                    QMessageBox.warning(dialog, "Error", "Invalid 2FA code. Ensure your device time is synced.")

            verify_btn.clicked.connect(verify_2fa)
            if not dialog.exec():
                return

        log_activity(username, "Successful login")
        session_id = save_session(username)
        if session_id:
            log_activity(username, f"Session created with ID: {session_id}")
        else:
            log_activity(username, "Failed to create session")
        self.main_window = ShadowCryptUI(username)
        self.main_window.show()
        self.close()

    def show_registration(self):
        dialog = RegistrationDialog(self)
        dialog.exec()

    def show_forgot_password(self):
        dialog = ForgotPasswordDialog(self)
        dialog.exec()

class RegistrationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register New User")
        self.setFixedSize(400, 500)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        header = HeaderWidget("Create Account", "Register a new user")
        header.setFixedHeight(150)
        layout.addWidget(header)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        layout.addWidget(self.email_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.register_btn = QPushButton("Register")
        self.register_btn.clicked.connect(self.register_user)
        layout.addWidget(self.register_btn, 0, Qt.AlignCenter)

        layout.addStretch()

    def register_user(self):
        email = self.email_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not email or not username or not password:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")
            return

        if "@" not in email or "." not in email:
            QMessageBox.warning(self, "Error", "Invalid email address.")
            return

        auth_data = load_auth_file()
        users = auth_data["users"]

        for user in users:
            if user["user"] == username:
                QMessageBox.warning(self, "Error", "Username already exists.")
                return
            if user.get("email") == email:
                QMessageBox.warning(self, "Error", "Email already registered.")
                return
            if user["role"] != "admin" and user.get("system_id") == SYSTEM_ID:
                QMessageBox.warning(self, "Error", "A user is already registered on this system. Please delete the existing user via the Admin Dashboard to register a new one.")
                return

        users.append({
            "email": email,
            "user": username,
            "pass": hash_password(password),
            "role": "user",
            "locked": False,
            "system_id": SYSTEM_ID,
            "theme": "light"
        })
        auth_data["users"] = users
        save_auth_file(auth_data)
        log_activity(username, f"User registered on system {SYSTEM_ID}")
        QMessageBox.information(self, "Success", "Registration successful! You can now log in.")
        self.accept()

class ForgotPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Recovery")
        self.setFixedSize(500, 500)
        self.otp = None
        self.otp_timestamp = None
        self.user_email = None
        self.username = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = HeaderWidget("Password Recovery", "We'll help you get back in")
        layout.addWidget(header)

        self.card = CardWidget()
        form_layout = QVBoxLayout(self.card)
        form_layout.setContentsMargins(40, 30, 40, 30)
        form_layout.setSpacing(20)

        self.user_identifier_label = QLabel("Username or Email:")
        self.user_identifier_label.setStyleSheet("font-weight: 500;")
        self.user_identifier_input = QLineEdit()
        self.user_identifier_input.setPlaceholderText("Enter your username or registered email")

        self.send_otp_btn = QPushButton("Send OTP")
        self.send_otp_btn.clicked.connect(self.send_otp)

        self.otp_label = QLabel("Enter OTP:")
        self.otp_label.setStyleSheet("font-weight: 500;")
        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("Enter the 6-digit OTP sent to your email")
        self.otp_label.hide()
        self.otp_input.hide()

        self.new_pass_label = QLabel("New Password:")
        self.new_pass_label.setStyleSheet("font-weight: 500;")
        self.new_pass_input = QLineEdit()
        self.new_pass_input.setPlaceholderText("Enter new password")
        self.new_pass_input.setEchoMode(QLineEdit.Password)
        self.new_pass_label.hide()
        self.new_pass_input.hide()

        self.confirm_pass_label = QLabel("Confirm Password:")
        self.confirm_pass_label.setStyleSheet("font-weight: 500;")
        self.confirm_pass_input = QLineEdit()
        self.confirm_pass_input.setPlaceholderText("Confirm new password")
        self.confirm_pass_input.setEchoMode(QLineEdit.Password)
        self.confirm_pass_label.hide()
        self.confirm_pass_input.hide()

        self.verify_otp_btn = QPushButton("Verify OTP")
        self.verify_otp_btn.clicked.connect(self.verify_otp)
        self.verify_otp_btn.hide()

        self.reset_btn = QPushButton("Reset Password")
        self.reset_btn.clicked.connect(self.reset_password)
        self.reset_btn.hide()

        form_layout.addWidget(self.user_identifier_label)
        form_layout.addWidget(self.user_identifier_input)
        form_layout.addWidget(self.send_otp_btn, 0, Qt.AlignCenter)
        form_layout.addWidget(self.otp_label)
        form_layout.addWidget(self.otp_input)
        form_layout.addWidget(self.verify_otp_btn, 0, Qt.AlignCenter)
        form_layout.addWidget(self.new_pass_label)
        form_layout.addWidget(self.new_pass_input)
        form_layout.addWidget(self.confirm_pass_label)
        form_layout.addWidget(self.confirm_pass_input)
        form_layout.addWidget(self.reset_btn, 0, Qt.AlignCenter)

        layout.addWidget(self.card)
        layout.addStretch()

    def send_otp(self):
            user_identifier = self.user_identifier_input.text().strip()
            if not user_identifier:
                QMessageBox.warning(self, "Error", "Please enter your username or email address")
                return

            try:
                auth_data = load_auth_file()
                user = None

                # Filter valid users with "user" key
                valid_users = [u for u in auth_data.get("users", []) if "user" in u]
                if len(valid_users) < len(auth_data.get("users", [])):
                    log_activity("system", "Detected invalid user entries missing 'user' key in auth data")

                # Check for user by username or email
                if "@" in user_identifier:
                    user = next((u for u in valid_users if u.get("email") == user_identifier), None)
                else:
                    user = next((u for u in valid_users if u["user"] == user_identifier), None)

                if not user:
                    QMessageBox.warning(self, "Error", "Username or email not found in our records.")
                    log_activity("unknown", f"Failed password recovery attempt with identifier: {user_identifier}")
                    return

                if not user.get("email"):
                    QMessageBox.warning(self, "Error", "No email address associated with this account.")
                    log_activity(user.get("user", "unknown"), "Failed password recovery attempt: No email associated")
                    return

                # Generate OTP and set expiration
                self.otp = str(secrets.randbelow(1000000)).zfill(6)
                self.otp_timestamp = datetime.now()
                self.user_email = user["email"]
                self.username = user["user"]

                subject = "ShadowCrypt Password Reset OTP"
                body = f"""Hello {self.username},

    Your OTP for password reset is: {self.otp}

    This OTP is valid for 10 minutes. If you didn't request this, please contact support.

    - The ShadowCrypt Team
    """
                msg = MIMEText(body)
                msg['Subject'] = subject
                msg['From'] = EMAIL_ADDRESS
                msg['To'] = self.user_email

                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                    server.sendmail(EMAIL_ADDRESS, [self.user_email], msg.as_string())

                self.user_identifier_label.hide()
                self.user_identifier_input.hide()
                self.send_otp_btn.hide()

                self.otp_label.show()
                self.otp_input.show()
                self.verify_otp_btn.show()

                log_activity(self.username, "OTP sent for password recovery")
                QMessageBox.information(self, "OTP Sent",
                                        f"A 6-digit OTP has been sent to {self.user_email}. Please check your inbox (and spam folder).")

            except Exception as e:
                log_activity(self.username or "unknown", f"Failed to send OTP: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to send OTP: {str(e)}")

    def verify_otp(self):
        entered_otp = self.otp_input.text().strip()

        if not entered_otp or len(entered_otp) != 6 or not entered_otp.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid 6-digit OTP")
            log_activity(self.username or "unknown", "Invalid OTP format entered")
            return

        # Check OTP expiration (10 minutes)
        if self.otp_timestamp and (datetime.now() - self.otp_timestamp) > timedelta(minutes=10):
            QMessageBox.warning(self, "Error", "OTP has expired. Please request a new OTP.")
            log_activity(self.username, "OTP verification failed: OTP expired")
            self.otp = None
            self.otp_timestamp = None
            self.user_identifier_label.show()
            self.user_identifier_input.show()
            self.send_otp_btn.show()
            self.otp_label.hide()
            self.otp_input.hide()
            self.verify_otp_btn.hide()
            return

        if entered_otp != self.otp:
            QMessageBox.warning(self, "Error", "Invalid OTP. Please try again.")
            log_activity(self.username, "OTP verification failed: Invalid OTP")
            return

        self.otp_label.hide()
        self.otp_input.hide()
        self.verify_otp_btn.hide()

        self.new_pass_label.show()
        self.new_pass_input.show()
        self.confirm_pass_label.show()
        self.confirm_pass_input.show()
        self.reset_btn.show()

        log_activity(self.username, "OTP verified successfully for password recovery")
        QMessageBox.information(self, "Success", "OTP verified. Please enter your new password.")

    def reset_password(self):
        new_password = self.new_pass_input.text()
        confirm_password = self.confirm_pass_input.text()

        if not new_password or not confirm_password:
            QMessageBox.warning(self, "Error", "Please fill in both password fields.")
            log_activity(self.username, "Password reset failed: Missing password fields")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            log_activity(self.username, "Password reset failed: Passwords do not match")
            return

        try:
            auth_data = load_auth_file()
            for user in auth_data["users"]:
                if user.get("user") == self.username and user.get("email") == self.user_email:
                    user["pass"] = hash_password(new_password)
                    break
            else:
                QMessageBox.critical(self, "Error", "User account not found.")
                log_activity(self.username, "Password reset failed: User account not found")
                return

            save_auth_file(auth_data)
            log_activity(self.username, "Password reset successfully")
            QMessageBox.information(self, "Success",
                                    "Your password has been reset successfully. You can now log in with your new password.")
            self.accept()

        except Exception as e:
            log_activity(self.username, f"Password reset failed: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error resetting password: {str(e)}")


class CustomDictionaryDialog(QDialog):
    def __init__(self, parent=None, username=None):
        super().__init__(parent)
        self.username = username
        self.setWindowTitle("Create Custom Dictionary")
        self.setFixedSize(600, 600)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        header = HeaderWidget("Custom Dictionary", "Define your own mappings")
        header.setFixedHeight(150)
        layout.addWidget(header)

        self.dict_name_input = QLineEdit()
        self.dict_name_input.setPlaceholderText("Dictionary Name (e.g., MyDict)")
        layout.addWidget(self.dict_name_input)

        self.binary_input = QTextEdit()
        self.binary_input.setPlaceholderText("Binary mappings (e.g., A:01000001,B:01000010,...)")
        self.binary_input.setMinimumHeight(100)
        layout.addWidget(self.binary_input)

        self.morse_input = QTextEdit()
        self.morse_input.setPlaceholderText("Morse mappings (e.g., A:.-,B:-...,...)")
        self.morse_input.setMinimumHeight(100)
        layout.addWidget(self.morse_input)

        self.save_btn = QPushButton("Save Dictionary")
        self.save_btn.clicked.connect(self.save_dictionary)
        layout.addWidget(self.save_btn, 0, Qt.AlignCenter)

        layout.addStretch()

    def save_dictionary(self):
        dict_name = self.dict_name_input.text().strip()
        binary_text = self.binary_input.toPlainText().strip()
        morse_text = self.morse_input.toPlainText().strip()

        if not dict_name or not binary_text or not morse_text:
            QMessageBox.warning(self, "Error", "Please fill in all fields.")
            return

        try:
            binary_dict = dict(item.split(":") for item in binary_text.split(",") if ":" in item)
            morse_dict = dict(item.split(":") for item in morse_text.split(",") if ":" in item)

            if not binary_dict or not morse_dict:
                QMessageBox.warning(self, "Error",
                                    "Invalid dictionary format. Use key:value pairs separated by commas.")
                return

            save_custom_dictionary(self.username, dict_name, binary_dict, morse_dict)
            log_activity(self.username, f"Saved custom dictionary: {dict_name}")
            QMessageBox.information(self, "Success", f"Custom dictionary '{dict_name}' saved successfully.")
            self.accept()
        except Exception as e:
            log_activity(self.username, f"Failed to save custom dictionary: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to save dictionary: {str(e)}")


class TwoFADialog(QDialog):
    def __init__(self, parent=None, username=None):
        super().__init__(parent)
        self.username = username
        self.secret = generate_2fa_secret()
        self.setWindowTitle("Setup 2FA with Google Authenticator")
        self.setFixedSize(400, 500)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        header = HeaderWidget("2FA Setup", "Scan this QR code with Google Authenticator")
        layout.addWidget(header)

        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(pyotp.totp.TOTP(self.secret).provisioning_uri(
            name=self.username, issuer_name="ShadowCrypt"))
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save("2fa_qr.png")

        qr_label = QLabel()
        pixmap = QPixmap("2fa_qr.png")
        qr_label.setPixmap(pixmap.scaled(200, 200, Qt.KeepAspectRatio))
        qr_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(qr_label)

        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("Enter the 6-digit code from Google Authenticator")
        layout.addWidget(self.otp_input)

        self.verify_btn = QPushButton("Verify and Enable 2FA")
        self.verify_btn.clicked.connect(self.verify_and_enable)
        layout.addWidget(self.verify_btn, 0, Qt.AlignCenter)

        layout.addStretch()

    def verify_and_enable(self):
        code = self.otp_input.text().strip()
        if not code or len(code) != 6 or not code.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid 6-digit code.")
            log_activity(self.username, "2FA setup failed: Invalid code format")
            return

        totp = pyotp.TOTP(self.secret, interval=30)
        if totp.verify(code, valid_window=1):  # Allow 30s drift
            save_2fa_secret(self.username, self.secret)
            log_activity(self.username, "2FA enabled successfully")
            QMessageBox.information(self, "Success", "2FA has been enabled successfully.")
            self.accept()
        else:
            log_activity(self.username, "2FA setup failed: Invalid TOTP code")
            QMessageBox.warning(self, "Error", "Invalid 2FA code. Please ensure your device time is synced and try again.")

class ShadowCryptUI(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle(f"ShadowCrypt - {self.username}")
        self.setGeometry(100, 100, 900, 700)
        self.setup_ui()
        self.apply_user_theme()

    def apply_user_theme(self):
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == self.username), None)
        if user and "theme" in user:
            QApplication.instance().apply_theme(user["theme"])

    def toggle_theme(self):
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == self.username), None)
        if not user:
            QMessageBox.critical(self, "Error", "User not found.")
            return

        current_theme = user.get("theme", "light")
        new_theme = "dark" if current_theme == "light" else "light"
        user["theme"] = new_theme
        save_auth_file(auth_data)
        QApplication.instance().apply_theme(new_theme)
        log_activity(self.username, f"Switched to {new_theme} theme")
        self.statusBar().showMessage(f"Switched to {new_theme} theme")
        self.update_theme_button_text()

    def update_theme_button_text(self):
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == self.username), None)
        if user and user.get("theme", "light") == "dark":
            self.theme_btn.setText("Switch to Light Theme")
        else:
            self.theme_btn.setText("Switch to Dark Theme")

    def update_2fa_button_text(self):
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == self.username), None)
        if user and user.get("2fa_enabled", False):
            self.twofa_btn.setText("Disable 2FA")
        else:
            self.twofa_btn.setText("Enable 2FA")

    def toggle_2fa(self):
        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == self.username), None)
        if not user:
            QMessageBox.critical(self, "Error", "User not found.")
            return

        if user.get("2fa_enabled", False):
            reply = QMessageBox.question(
                self,
                "Confirm Disable 2FA",
                "Are you sure you want to disable 2FA? This will reduce your account security.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                disable_2fa(self.username)
                self.update_2fa_button_text()
                self.statusBar().showMessage("2FA disabled")
        else:
            dialog = TwoFADialog(self, self.username)
            if dialog.exec():
                self.update_2fa_button_text()
                self.statusBar().showMessage("2FA enabled")

    def setup_ui(self):
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(30, 20, 30, 30)
        self.main_layout.setSpacing(20)

        self.header = HeaderWidget("ShadowCrypt", f"Welcome, {self.username}")
        self.main_layout.addWidget(self.header)

        self.card = QFrame()
        self.card.setObjectName("mainCard")
        self.card_layout = QVBoxLayout(self.card)
        self.card_layout.setContentsMargins(20, 20, 20, 20)
        self.card_layout.setSpacing(15)

        # Add logout button
        logout_layout = QHBoxLayout()
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setObjectName("secondary")
        self.logout_btn.clicked.connect(self.logout)
        logout_layout.addStretch()
        logout_layout.addWidget(self.logout_btn)
        self.card_layout.addLayout(logout_layout)

        self.tabs = QTabWidget()
        self.setup_crypto_tab()
        self.setup_dictionary_tab()
        self.setup_settings_tab()
        self.card_layout.addWidget(self.tabs)

        self.main_layout.addWidget(self.card)
        self.main_layout.addStretch()

        self.status_bar = self.statusBar()
        self.statusBar().showMessage(f"Ready - User {self.username}")

    def logout(self):
        """Handle logout by resetting session and returning to login window."""
        reset_session()
        log_activity(self.username, "Logged out")
        self.close()
        login_window = LoginWindow()
        login_window.show()

    def change_password(self):
        current_pass = self.current_pass_input.text()
        new_pass = self.new_pass_input.text()
        confirm_new_pass = self.confirm_new_pass_input.text()

        if not current_pass or not new_pass or not confirm_new_pass:
            QMessageBox.warning(self, "Error", "Please fill in all password fields.")
            return

        if new_pass != confirm_new_pass:
            QMessageBox.warning(self, "Error", "New password and confirmation do not match.")
            return

        auth_data = load_auth_file()
        user = next((u for u in auth_data["users"] if u["user"] == self.username and u["role"] == "user"), None)

        if not user:
            QMessageBox.critical(self, "Error", f"{self.username} account not found.")
            return

        if user["pass"] != hash_password(current_pass):
            log_activity(self.username, f"{self.username} password change failed - incorrect current password")
            QMessageBox.warning(self, "Error", "Current password is incorrect.")
            return

        user["pass"] = hash_password(new_pass)
        save_auth_file(auth_data)
        log_activity(self.username, f"{self.username} password changed successfully")
        QMessageBox.information(self, "Success", "Password changed successfully.")
        reset_all_user_sessions(self.username)
        log_activity(self.username, "All sessions reset due to password change")
        return True
        self.current_pass_input.clear()
        self.new_pass_input.clear()
        self.confirm_new_pass_input.clear()
        self.statusBar().showMessage("Password updated successfully!")

    def setup_dictionary_tab(self):
        self.dictionary_tab = QWidget()
        self.dictionary_layout = QVBoxLayout(self.dictionary_tab)
        self.dictionary_layout.setContentsMargins(10, 10, 10, 10)
        self.dictionary_layout.setSpacing(15)

        dict_label = QLabel("Dictionary Operations")
        dict_label.setObjectName("sectionLabel")
        self.dictionary_layout.addWidget(dict_label)

        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(15)

        mode_label = QLabel("Dictionary Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Authentic", "Secret", "Custom"])
        self.mode_combo.currentTextChanged.connect(self.update_custom_dict_ui)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        self.dictionary_layout.addLayout(mode_layout)

        self.custom_dict_layout = QHBoxLayout()
        self.custom_dict_combo = QComboBox()
        self.custom_dict_combo.addItem("Select Custom Dictionary")
        self.load_custom_dicts()
        self.custom_dict_combo.currentTextChanged.connect(self.load_selected_dict)
        self.create_dict_btn = QPushButton("Create Custom Dictionary")
        self.create_dict_btn.clicked.connect(self.show_custom_dict_dialog)
        self.custom_dict_layout.addWidget(self.custom_dict_combo)
        self.custom_dict_layout.addWidget(self.create_dict_btn)
        self.custom_dict_layout.setEnabled(False)
        self.dictionary_layout.addLayout(self.custom_dict_layout)

        self.operation_group = QButtonGroup()
        op_layout = QHBoxLayout()
        op_layout.setSpacing(15)

        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.operation_group.addButton(self.encrypt_radio)
        self.operation_group.addButton(self.decrypt_radio)
        self.encrypt_radio.setChecked(True)

        op_layout.addWidget(QLabel("Operation:"))
        op_layout.addWidget(self.encrypt_radio)
        op_layout.addWidget(self.decrypt_radio)
        op_layout.addStretch()
        self.dictionary_layout.addLayout(op_layout)

        self.dict_input_text = QLineEdit()
        self.dict_input_text.setPlaceholderText("Enter text to translate...")
        self.dictionary_layout.addWidget(self.dict_input_text)

        self.translate_button = QPushButton("Translate")
        self.translate_button.setMinimumHeight(40)
        self.translate_button.clicked.connect(self.translate_text)
        self.dictionary_layout.addWidget(self.translate_button)

        output_label = QLabel("Result:")
        output_label.setObjectName("sectionLabel")
        self.dictionary_layout.addWidget(output_label)

        self.dict_output_text = QTextEdit()
        self.dict_output_text.setPlaceholderText("Translation result will appear here...")
        self.dict_output_text.setReadOnly(True)
        self.dict_output_text.setMinimumHeight(150)
        self.dictionary_layout.addWidget(self.dict_output_text)

        self.tabs.addTab(self.dictionary_tab, "Dictionary")

    def setup_crypto_tab(self):
        self.crypto_tab = QWidget()
        self.crypto_layout = QVBoxLayout(self.crypto_tab)
        self.crypto_layout.setContentsMargins(10, 10, 10, 15)
        self.crypto_layout.setSpacing(15)

        # Operation toggle button
        self.operation_toggle = QPushButton("Switch to File Operations")
        self.operation_toggle.setObjectName("operationToggle")
        self.operation_toggle.setCheckable(True)
        self.operation_toggle.clicked.connect(self.toggle_crypto_operation)
        self.crypto_layout.addWidget(self.operation_toggle)

        # Section label
        self.crypto_label = QLabel("Cryptography Operations")
        self.crypto_label.setObjectName("sectionLabel")
        self.crypto_layout.addWidget(self.crypto_label)

        # Text operations
        self.text_label = QLabel("Text Operations")
        self.text_label.setStyleSheet("font-weight: 500;")
        self.crypto_layout.addWidget(self.text_label)

        self.input_text = QPlainTextEdit()
        self.input_text.setPlaceholderText("Enter text to encrypt/decrypt here...")
        self.input_text.setMinimumHeight(120)
        self.crypto_layout.addWidget(self.input_text)

        self.key_layout = QHBoxLayout()
        self.key_label = QLabel("Encryption Key:")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter or generate an 8-digit key")
        self.generate_key_btn = QPushButton("Generate Key")
        self.generate_key_btn.setObjectName("secondary")
        self.generate_key_btn.clicked.connect(self.generate_key)
        self.key_layout.addWidget(self.key_label)
        self.key_layout.addWidget(self.key_input, 1)
        self.key_layout.addWidget(self.generate_key_btn)
        self.crypto_layout.addLayout(self.key_layout)

        self.text_button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt Text")
        self.encrypt_button.setMinimumHeight(40)
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.decrypt_button = QPushButton("Decrypt Text")
        self.decrypt_button.setMinimumHeight(40)
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.text_button_layout.addWidget(self.encrypt_button)
        self.text_button_layout.addWidget(self.decrypt_button)
        self.crypto_layout.addLayout(self.text_button_layout)

        # File operations
        self.file_label = QLabel("File Operations")
        self.file_label.setStyleSheet("font-weight: 500;")
        self.crypto_layout.addWidget(self.file_label)

        self.file_select_layout = QHBoxLayout()
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("color: #7f8c8d; font-size: 14px;")
        self.select_file_btn = QPushButton("Select File")
        self.select_file_btn.setObjectName("secondary")
        self.select_file_btn.clicked.connect(self.select_file)
        self.file_select_layout.addWidget(self.file_path_label, 1)
        self.file_select_layout.addWidget(self.select_file_btn)
        self.crypto_layout.addLayout(self.file_select_layout)

        self.file_key_layout = QHBoxLayout()
        self.file_key_label = QLabel("Encryption Key:")
        self.file_key_input = QLineEdit()
        self.file_key_input.setPlaceholderText("Enter or generate an 8-digit key")
        self.file_generate_key_btn = QPushButton("Generate Key")
        self.file_generate_key_btn.setObjectName("secondary")
        self.file_generate_key_btn.clicked.connect(self.generate_key)
        self.file_key_layout.addWidget(self.file_key_label)
        self.file_key_layout.addWidget(self.file_key_input, 1)
        self.file_key_layout.addWidget(self.file_generate_key_btn)
        self.crypto_layout.addLayout(self.file_key_layout)

        self.file_button_layout = QHBoxLayout()
        self.encrypt_file_btn = QPushButton("Encrypt File")
        self.encrypt_file_btn.setMinimumHeight(40)
        self.encrypt_file_btn.clicked.connect(self.encrypt_file)
        self.decrypt_file_btn = QPushButton("Decrypt File")
        self.decrypt_file_btn.setMinimumHeight(40)
        self.decrypt_file_btn.clicked.connect(self.decrypt_file)
        self.file_button_layout.addWidget(self.encrypt_file_btn)
        self.file_button_layout.addWidget(self.decrypt_file_btn)
        self.crypto_layout.addLayout(self.file_button_layout)

        # Output section
        self.output_label = QLabel("Result:")
        self.output_label.setObjectName("sectionLabel")
        self.crypto_layout.addWidget(self.output_label)

        self.output_text = QPlainTextEdit()
        self.output_text.setPlaceholderText("Encrypted/decrypted result or file operation status will appear here...")
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumHeight(120)
        self.crypto_layout.addWidget(self.output_text)

        # List of file-related widgets for toggling (only widgets, no layouts)
        self.file_widgets = [
            self.file_label,
            self.file_path_label,
            self.select_file_btn,
            self.file_key_label,
            self.file_key_input,
            self.file_generate_key_btn,
            self.encrypt_file_btn,
            self.decrypt_file_btn
        ]

        # Initial state: show text widgets, hide file widgets
        self.toggle_crypto_operation(False)
        self.tabs.addTab(self.crypto_tab, "Cryptography")

    def toggle_crypto_operation(self, checked):
        self.operation_toggle.setText("Switch to Text Operations" if checked else "Switch to File Operations")

        # Text operation widgets
        text_widgets = [
            self.text_label,
            self.input_text,
            self.key_label,
            self.key_input,
            self.generate_key_btn,
            self.encrypt_button,
            self.decrypt_button
        ]

        # Toggle visibility
        for widget in text_widgets:
            widget.setVisible(not checked)
        for widget in self.file_widgets:
            widget.setVisible(checked)

        self.output_label.setVisible(True)
        self.output_text.setVisible(True)
        self.statusBar().showMessage(f"Switched to {'File' if checked else 'Text'} Operations")

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            "",
            "All Files (*.*)"
        )
        if file_path:
            self.file_path_label.setText(os.path.basename(file_path))
            self.selected_file_path = file_path
            self.output_text.setPlainText(f"Selected file: {os.path.basename(file_path)}")
            self.statusBar().showMessage(f"Selected file: {os.path.basename(file_path)}")
            log_activity(self.username, f"Selected file for cryptography: {os.path.basename(file_path)}")
        else:
            self.file_path_label.setText("No file selected")
            self.output_text.setPlainText("No file selected")
            self.statusBar().showMessage("File selection cancelled")
            log_activity(self.username, "File selection cancelled")

    def generate_key(self):
        key = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
        # Set key to appropriate input based on operation mode
        if self.operation_toggle.isChecked():
            self.file_key_input.setText(key)
        else:
            self.key_input.setText(key)
        self.statusBar().showMessage("Generated new 8-digit encryption key")
        log_activity(self.username, "Generated new encryption key")

    def encrypt_text(self):
        text = self.input_text.toPlainText().strip()
        key = self.key_input.text().strip()

        if not text:
            QMessageBox.warning(self, "Error", "Please enter text to encrypt.")
            self.statusBar().showMessage("Text encryption failed: No input text")
            return
        if not key or len(key) != 8 or not key.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid 8-digit key.")
            self.statusBar().showMessage("Text encryption failed: Invalid key")
            return

        try:
            key_material = key.encode()
            derived_key = hkdf.hkdf_extract(b'OgAI7TeD3HsMM', key_material)
            derived_key = hkdf.hkdf_expand(derived_key, b'shadowcrypt-encryption', 32)
            fernet_key = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key)
            encrypted_text = cipher.encrypt(text.encode()).decode()
            self.output_text.setPlainText(encrypted_text)
            self.statusBar().showMessage("Text encrypted successfully!")
            log_activity(self.username, "Encrypted text successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Text encryption failed: {str(e)}")
            self.statusBar().showMessage("Text encryption failed")
            log_activity(self.username, f"Text encryption failed: {str(e)}")

    def decrypt_text(self):
        text = self.input_text.toPlainText().strip()
        key = self.key_input.text().strip()

        if not text:
            QMessageBox.warning(self, "Error", "Please enter text to decrypt.")
            self.statusBar().showMessage("Text decryption failed: No input text")
            return
        if not key or len(key) != 8 or not key.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid 8-digit key.")
            self.statusBar().showMessage("Text decryption failed: Invalid key")
            return

        try:
            key_material = key.encode()
            derived_key = hkdf.hkdf_extract(b'OgAI7TeD3HsMM', key_material)
            derived_key = hkdf.hkdf_expand(derived_key, b'shadowcrypt-encryption', 32)
            fernet_key = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key)
            decrypted_text = cipher.decrypt(text.encode()).decode()
            self.output_text.setPlainText(decrypted_text)
            self.statusBar().showMessage("Text decrypted successfully!")
            log_activity(self.username, "Decrypted text successfully")
        except InvalidToken:
            QMessageBox.critical(self, "Error", "Decryption failed: Invalid key or corrupted text.")
            self.statusBar().showMessage("Text decryption failed")
            log_activity(self.username, "Text decryption failed: InvalidToken")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Text decryption failed: {str(e)}")
            self.statusBar().showMessage("Text decryption failed")
            log_activity(self.username, f"Text decryption failed: {str(e)}")

    def encrypt_file(self):
        if not hasattr(self, 'selected_file_path') or not self.selected_file_path:
            QMessageBox.warning(self, "Error", "Please select a file to encrypt.")
            self.statusBar().showMessage("File encryption failed: No file selected")
            return

        key = self.file_key_input.text().strip()
        if not key or len(key) != 8 or not key.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid 8-digit key.")
            self.statusBar().showMessage("File encryption failed: Invalid key")
            return

        try:
            key_material = key.encode()
            derived_key = hkdf.hkdf_extract(b'OgAI7TeD3HsMM', key_material)
            derived_key = hkdf.hkdf_expand(derived_key, b'shadowcrypt-encryption', 32)
            fernet_key = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key)

            input_file = self.selected_file_path
            output_file = os.path.splitext(input_file)[0] + ".enc"
            chunk_size = 1024 * 1024  # 1MB chunks

            with open(input_file, 'rb') as f_in:
                file_data = f_in.read()
            encrypted_data = cipher.encrypt(file_data)

            with open(output_file, 'wb') as f_out:
                f_out.write(encrypted_data)

            self.output_text.setPlainText(f"File encrypted successfully!\nSaved as: {os.path.basename(output_file)}")
            self.statusBar().showMessage("File encrypted successfully!")
            log_activity(self.username,
                         f"Encrypted file: {os.path.basename(input_file)} to {os.path.basename(output_file)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"File encryption failed: {str(e)}")
            self.statusBar().showMessage("File encryption failed")
            log_activity(self.username, f"File encryption failed: {str(e)}")

    def decrypt_file(self):
        if not hasattr(self, 'selected_file_path') or not self.selected_file_path:
            QMessageBox.warning(self, "Error", "Please select a file to decrypt.")
            self.statusBar().showMessage("File decryption failed: No file selected")
            return

        key = self.file_key_input.text().strip()
        if not key or len(key) != 8 or not key.isdigit():
            QMessageBox.warning(self, "Error", "Please enter a valid 8-digit key.")
            self.statusBar().showMessage("File decryption failed: Invalid key")
            return

        try:
            key_material = key.encode()
            derived_key = hkdf.hkdf_extract(b'OgAI7TeD3HsMM', key_material)
            derived_key = hkdf.hkdf_expand(derived_key, b'shadowcrypt-encryption', 32)
            fernet_key = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key)

            input_file = self.selected_file_path
            output_file = os.path.splitext(input_file)[0] + ".dec"
            chunk_size = 1024 * 1024  # 1MB chunks

            with open(input_file, 'rb') as f_in:
                encrypted_data = f_in.read()
            decrypted_data = cipher.decrypt(encrypted_data)

            with open(output_file, 'wb') as f_out:
                f_out.write(decrypted_data)

            self.output_text.setPlainText(f"File decrypted successfully!\nSaved as: {os.path.basename(output_file)}")
            self.statusBar().showMessage("File decrypted successfully!")
            log_activity(self.username,
                         f"Decrypted file: {os.path.basename(input_file)} to {os.path.basename(output_file)}")
        except InvalidToken:
            QMessageBox.critical(self, "Error", "File decryption failed: Invalid key or corrupted file.")
            self.statusBar().showMessage("File decryption failed")
            log_activity(self.username, "File decryption failed: InvalidToken")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"File decryption failed: {str(e)}")
            self.statusBar().showMessage("File decryption failed")
            log_activity(self.username, f"File decryption failed: {str(e)}")

    def setup_settings_tab(self):
        self.settings_tab = QWidget()
        self.settings_layout = QVBoxLayout(self.settings_tab)
        self.settings_layout.setContentsMargins(10, 10, 10, 10)
        self.settings_layout.setSpacing(15)

        settings_label = QLabel("User Settings")
        settings_label.setObjectName("sectionLabel")
        self.settings_layout.addWidget(settings_label)

        change_pass_label = QLabel("Change Password")
        change_pass_label.setStyleSheet("font-weight: 500;")
        self.settings_layout.addWidget(change_pass_label)

        self.current_pass_input = QLineEdit()
        self.current_pass_input.setPlaceholderText("Enter current password")
        self.current_pass_input.setEchoMode(QLineEdit.Password)
        self.settings_layout.addWidget(self.current_pass_input)

        self.new_pass_input = QLineEdit()
        self.new_pass_input.setPlaceholderText("Enter new password")
        self.new_pass_input.setEchoMode(QLineEdit.Password)
        self.settings_layout.addWidget(self.new_pass_input)

        self.confirm_new_pass_input = QLineEdit()
        self.confirm_new_pass_input.setPlaceholderText("Confirm new password")
        self.confirm_new_pass_input.setEchoMode(QLineEdit.Password)
        self.settings_layout.addWidget(self.confirm_new_pass_input)

        self.change_pass_btn = QPushButton("Change Password")
        self.change_pass_btn.clicked.connect(self.change_password)
        self.settings_layout.addWidget(self.change_pass_btn, 0, Qt.AlignCenter)

        theme_label = QLabel("Theme")
        theme_label.setStyleSheet("font-weight: 500;")
        self.settings_layout.addWidget(theme_label)

        self.theme_btn = QPushButton("Switch to Dark Theme")
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.update_theme_button_text()
        self.settings_layout.addWidget(self.theme_btn, 0, Qt.AlignCenter)

        twofa_label = QLabel("Two-Factor Authentication")
        twofa_label.setStyleSheet("font-weight: 500;")
        self.settings_layout.addWidget(twofa_label)

        self.twofa_btn = QPushButton("Enable 2FA")
        self.twofa_btn.clicked.connect(self.toggle_2fa)
        self.update_2fa_button_text()
        self.settings_layout.addWidget(self.twofa_btn, 0, Qt.AlignCenter)

        self.settings_layout.addStretch()

        self.tabs.addTab(self.settings_tab, "Settings")

    def load_custom_dicts(self):
        try:
            docs = db.collection("custom_dictionaries").where("username", "==", self.username).get()
            self.custom_dict_combo.clear()
            self.custom_dict_combo.addItem("Select Custom Dictionary")
            for doc in docs:
                self.custom_dict_combo.addItem(doc.id)
        except Exception as e:
            log_activity(self.username, f"Failed to load custom dictionaries: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to load custom dictionaries: {str(e)}")

    def update_custom_dict_ui(self):
        is_custom = self.mode_combo.currentText() == "Custom"
        self.custom_dict_layout.setEnabled(is_custom)
        if is_custom and self.custom_dict_combo.currentText() == "Select Custom Dictionary":
            self.translate_button.setEnabled(False)
        else:
            self.translate_button.setEnabled(True)

    def load_selected_dict(self):
        dict_name = self.custom_dict_combo.currentText()
        if dict_name == "Select Custom Dictionary":
            self.translate_button.setEnabled(False)
            return
        try:
            dict_data = load_custom_dictionary(dict_name)
            if dict_data:
                self.current_binary_dict = dict_data["binary"]
                self.current_morse_dict = dict_data["morse"]
                self.current_binary_reversed = {v: k for k, v in self.current_binary_dict.items()}
                self.current_morse_reversed = {v: k for k, v in self.current_morse_dict.items()}
                self.translate_button.setEnabled(True)
                log_activity(self.username, "load_custom_dictionary", dict_name,
                                f"Loaded custom dictionary: {dict_name}")
                self.statusBar().showMessage(f"Loaded custom dictionary: {dict_name}")
            else:
                QMessageBox.warning(self, "Error", f"Custom dictionary '{dict_name}' not found.")
                self.translate_button.setEnabled(False)
        except Exception as e:
            log_activity(self.username, f"Failed to load custom dictionary: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to load dictionary: {str(e)}")
            self.translate_button.setEnabled(False)

    def show_custom_dict_dialog(self):
        dialog = CustomDictionaryDialog(self, self.username)
        if dialog.exec():
            self.load_custom_dicts()
            self.custom_dict_combo.setCurrentText(dialog.dict_name_input.text())

    def translate_text(self):
        mode = self.mode_combo.currentText()
        text = self.dict_input_text.text()
        operation = "encrypt" if self.encrypt_radio.isChecked() else "decrypt"

        if not text:
            QMessageBox.warning(self, "Error", "Please enter text to translate")
            return

        try:
            if mode == "Authentic":
                binary_dict = A_BINARY_CODE_DICT
                morse_dict = A_MORSE_CODE_DICT
                binary_reversed = A_BINARY_CODE_REVERSED
                morse_reversed = A_MORSE_CODE_REVERSED
            elif mode == "Secret":
                binary_dict = S_BINARY_CODE_DICT
                morse_dict = S_MORSE_CODE_DICT
                binary_reversed = S_BINARY_CODE_REVERSED
                morse_reversed = S_MORSE_CODE_REVERSED
            elif mode == "Custom":
                if not hasattr(self,
                               "current_binary_dict") or not self.custom_dict_combo.currentText() or self.custom_dict_combo.currentText() == "Select Custom Dictionary":
                    QMessageBox.warning(self, "Error", "Please select a custom dictionary.")
                    return
                binary_dict = self.current_binary_dict
                morse_dict = self.current_morse_dict
                binary_reversed = self.current_binary_reversed
                morse_reversed = self.current_morse_reversed
            else:
                raise ValueError("Invalid dictionary mode")

            if operation == "encrypt":
                binary = " ".join(binary_dict.get(c, '') for c in text)
                morse = " ".join(morse_dict.get(c.upper(), '') for c in text)
                self.dict_output_text.setText(f"Binary:\n{binary}\n\nMorse:\n{morse}")
            else:
                binary_text = "".join(binary_reversed.get(c, '') for c in text.split())
                morse_text = "".join(morse_reversed.get(c, '') for c in text.split())
                self.dict_output_text.setText(f"Binary to Text:\n{binary_text}\n\nMorse to Text:\n{morse_text}")

            log_activity(self.username, f"Translated text using {mode.lower()} mode ({operation})")
            self.statusBar().showMessage("Text translated successfully!")
        except Exception as e:
            log_activity(self.username, f"Translation failed: {str(e)}")
            QMessageBox.critical(self, "Error", f"Translation failed: {str(e)}")
            self.statusBar().showMessage("Translation failed")

if __name__ == "__main__":
    app = AuthApp(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())
