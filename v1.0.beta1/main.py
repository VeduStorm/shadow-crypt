#v1.0.beta1
import sys
import os
import hashlib
import json
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QMessageBox,
    QTabWidget, QComboBox, QRadioButton, QButtonGroup
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet
from easygui import passwordbox, enterbox


def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


# Constants
AUTH_FILE = resource_path('data/auth.json')
SETUP_MARKER = resource_path("data/setup_complete.txt")
DATA_DIR = resource_path("data")

# Dictionaries (moved to a separate section for clarity)
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


def is_first_time_setup():
    return not os.path.exists(SETUP_MARKER)


def run_initial_setup():
    """Create necessary directories and files"""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    # Initialize auth file if it doesn't exist
    if not os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, 'w') as f:
            json.dump({"users": []}, f)

    # Mark setup as complete
    with open(SETUP_MARKER, 'w') as f:
        f.write("Setup completed")


def hash_password(password):
    """Hash the password using double SHA512"""
    h = hashlib.new('SHA512')
    h.update(password.encode())
    password = h.hexdigest()
    h.update(password.encode())
    return h.hexdigest()


def verify_password():
    """Verify user credentials with username support"""
    try:
        with open(AUTH_FILE, 'r') as file:
            auth_data = json.load(file)
    except FileNotFoundError:
        print("Password database not found!")
        sys.exit()

    for attempt in range(3):
        username = enterbox("Enter username:", "Authentication")
        if not username:
            continue

        entered_password = passwordbox("Enter password:")
        if not entered_password:
            continue

        # Find user in auth data
        user = None
        for u in auth_data['users']:
            if u['username'] == username:
                user = u
                break

        if not user:
            print("User not found!")
            if attempt < 2:
                print("Try Again!")
                continue
            else:
                print("Access Denied!")
                sys.exit()

        # Verify password
        hashed_input = hash_password(entered_password)
        if hashed_input == user['password']:
            return username
        elif attempt < 2:
            print("Try Again! Wrong password.")
        else:
            print("Access Denied!")
            sys.exit()

    return None


def add_new_user(username, password):
    """Add a new user to the system"""
    try:
        with open(AUTH_FILE, 'r') as file:
            auth_data = json.load(file)
    except FileNotFoundError:
        print("Password database not found!")
        sys.exit()

    # Check if username exists
    for user in auth_data['users']:
        if user['username'] == username:
            print("Username already exists!")
            return False

    # Add new user
    hashed_pw = hash_password(password)
    new_user = {
        "username": username,
        "password": hashed_pw
    }
    auth_data['users'].append(new_user)

    with open(AUTH_FILE, 'w') as f:
        json.dump(auth_data, f, indent=4)

    return True


class ShadowCryptUI(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.initUI()

    def initUI(self):
        self.setWindowTitle(f"Shadow Crypt - {self.username}")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon(resource_path('icon.png')))

        # Main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout()
        self.main_widget.setLayout(self.main_layout)

        # Title label
        self.title_label = QLabel("Shadow Crypt")
        self.title_label.setFont(QFont('Arial', 24))
        self.title_label.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(self.title_label)

        # Tab widget for different functionalities
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        # Cryptography tab
        self.crypto_tab = QWidget()
        self.crypto_layout = QVBoxLayout()
        self.crypto_tab.setLayout(self.crypto_layout)

        self.crypto_label = QLabel("Cryptography Operations")
        self.crypto_label.setFont(QFont('Arial', 14))
        self.crypto_layout.addWidget(self.crypto_label)

        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.setFont(QFont('Arial', 14))
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.crypto_layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.setFont(QFont('Arial', 14))
        self.decrypt_button.clicked.connect(self.decrypt_file)
        self.crypto_layout.addWidget(self.decrypt_button)

        self.tabs.addTab(self.crypto_tab, "Cryptography")

        # Dictionary tab
        self.dictionary_tab = QWidget()
        self.dictionary_layout = QVBoxLayout()
        self.dictionary_tab.setLayout(self.dictionary_layout)

        self.dictionary_label = QLabel("Dictionary Operations")
        self.dictionary_label.setFont(QFont('Arial', 14))
        self.dictionary_layout.addWidget(self.dictionary_label)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Authentic", "Secret"])
        self.dictionary_layout.addWidget(self.mode_combo)

        self.operation_group = QButtonGroup()
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.operation_group.addButton(self.encrypt_radio)
        self.operation_group.addButton(self.decrypt_radio)
        self.encrypt_radio.setChecked(True)

        self.operation_layout = QHBoxLayout()
        self.operation_layout.addWidget(self.encrypt_radio)
        self.operation_layout.addWidget(self.decrypt_radio)
        self.dictionary_layout.addLayout(self.operation_layout)

        self.input_text = QLineEdit()
        self.input_text.setPlaceholderText("Enter text to translate")
        self.dictionary_layout.addWidget(self.input_text)

        self.translate_button = QPushButton("Translate")
        self.translate_button.setFont(QFont('Arial', 14))
        self.translate_button.clicked.connect(self.translate_text)
        self.dictionary_layout.addWidget(self.translate_button)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.dictionary_layout.addWidget(self.output_text)

        self.tabs.addTab(self.dictionary_tab, "Dictionary")

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage(f"Welcome {self.username}!")

    def encrypt_file(self):
        try:
            with open(resource_path('encrypt.txt')) as f:
                encrypt = ''.join(f.readlines())

            key = Fernet.generate_key()
            with open(resource_path("refKey.txt"), "wb") as f:
                f.write(key)

            refKey = Fernet(key)
            encryptbyte = bytes(encrypt, 'utf-8')
            encrypted = refKey.encrypt(encryptbyte)
            with open(resource_path("encrypted.txt"), "wb") as f:
                f.write(encrypted)

            if os.path.exists(resource_path("encrypt.txt")):
                os.remove(resource_path("encrypt.txt"))

            QMessageBox.information(self, "Success", "File Encrypted Successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def decrypt_file(self):
        try:
            with open(resource_path('encrypted.txt'), 'rb') as f:
                enc = f.read()

            with open(resource_path('refKey.txt'), 'rb') as f:
                refKeybyt = f.read()

            keytouse = Fernet(refKeybyt)
            decrypted = keytouse.decrypt(enc)
            with open(resource_path("decrypted.txt"), "wb") as f:
                f.write(decrypted)

            if os.path.exists(resource_path("encrypted.txt")):
                os.remove(resource_path("encrypted.txt"))
            if os.path.exists(resource_path("refKey.txt")):
                os.remove(resource_path("refKey.txt"))

            QMessageBox.information(self, "Success", "File Decrypted Successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def translate_text(self):
        mode = self.mode_combo.currentText()
        text = self.input_text.text()
        operation = "encrypt" if self.encrypt_radio.isChecked() else "decrypt"

        if mode == "Authentic":
            if operation == "encrypt":
                binary = " ".join(A_BINARY_CODE_DICT.get(c, '') for c in text)
                morse = " ".join(A_MORSE_CODE_DICT.get(c.upper(), '') for c in text)
                self.output_text.setText(f"Binary: {binary}\nMorse: {morse}")
            else:
                binary_text = "".join(A_BINARY_CODE_REVERSED.get(c, '') for c in text.split())
                morse_text = "".join(A_MORSE_CODE_REVERSED.get(c, '') for c in text.split())
                self.output_text.setText(f"Binary to Text: {binary_text}\nMorse to Text: {morse_text}")
        elif mode == "Secret":
            if operation == "encrypt":
                binary = " ".join(S_BINARY_CODE_DICT.get(c, '') for c in text)
                morse = " ".join(S_MORSE_CODE_DICT.get(c.upper(), '') for c in text)
                self.output_text.setText(f"Binary: {binary}\nMorse: {morse}")
            else:
                binary_text = "".join(S_BINARY_CODE_REVERSED.get(c, '') for c in text.split())
                morse_text = "".join(S_MORSE_CODE_REVERSED.get(c, '') for c in text.split())
                self.output_text.setText(f"Binary to Text: {binary_text}\nMorse to Text: {morse_text}")


if __name__ == '__main__':
    # First-time setup check
    if is_first_time_setup():
        run_initial_setup()

    # Check if we have any users
    with open(AUTH_FILE, 'r') as f:
        auth_data = json.load(f)

    if not auth_data['users']:
        print("No users found. Creating first user.")
        username = enterbox("Create a username:", "First-time Setup")
        if not username:
            sys.exit()

        password = passwordbox("Create a password:")
        if not password:
            sys.exit()

        if add_new_user(username, password):
            print(f"User {username} created successfully!")
        else:
            sys.exit()

    # Normal authentication
    username = verify_password()
    if username:
        app = QApplication(sys.argv)
        window = ShadowCryptUI(username)
        window.show()
        sys.exit(app.exec_())