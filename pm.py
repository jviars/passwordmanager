import os
import json
import base64
import secrets
import string
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import pyotp
import qrcode
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QLineEdit, QTreeWidget,
    QTreeWidgetItem, QMessageBox, QInputDialog, QScrollArea, QSizePolicy)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QPixmap, QFont, QFontDatabase
import qdarktheme
from pathlib import Path

class PasswordManager:
    def __init__(self, db_file="passwords.dat"):
        self.db_file = db_file
        self.master_password = None
        self.salt = None
        self.key = None
        self.data = {}
        self.email = None
        self.otp_secret = None  # Persisted 2FA secret

    def initialize(self, email, master_password):
        self.email = email
        self.master_password = master_password
        self.salt = get_random_bytes(16)
        self.key = self.derive_key(master_password, self.salt)
        self.save_data()

    def derive_key(self, master_password, salt):
        return PBKDF2(master_password, salt, dkLen=32, count=1000000)

    def pad(self, txt):
        bs = AES.block_size
        padding_len = bs - len(txt) % bs
        return txt + bytes([padding_len]) * padding_len

    def unpad(self, txt):
        padding_len = txt[-1]
        return txt[:-padding_len]

    def encrypt(self, plaintext):
        IV = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, IV)
        padded_text = self.pad(plaintext.encode("utf-8"))
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(IV + ciphertext).decode("utf-8")

    def decrypt(self, b64_ciphertext):
        data = base64.b64decode(b64_ciphertext)
        IV = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, IV)
        padded_plaintext = cipher.decrypt(ciphertext)
        return self.unpad(padded_plaintext).decode("utf-8")

    def add_entry(self, account, username, password):
        entry = {"username": username, "password": password}
        encrypted_entry = self.encrypt(json.dumps(entry))
        self.data[account] = encrypted_entry
        self.save_data()

    def get_entry(self, account):
        enc_entry = self.data.get(account)
        if not enc_entry:
            return None
        plaintext = self.decrypt(enc_entry)
        return json.loads(plaintext)

    def get_all_accounts(self):
        return list(self.data.keys())

    def save_data(self):
        with open(self.db_file, "w") as f:
            json.dump({
                "email": self.email,
                "salt": base64.b64encode(self.salt).decode("utf-8") if self.salt else None,
                "data": self.data,
                "otp_secret": self.otp_secret
            }, f)

    def load_data(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, "r") as f:
                content = json.load(f)
                self.email = content.get("email")
                self.salt = base64.b64decode(content["salt"]) if content.get("salt") else None
                self.key = self.derive_key(self.master_password, self.salt)
                self.data = content.get("data", {})
                self.otp_secret = content.get("otp_secret")
            return True
        return False

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_2fa_secret():
    return pyotp.random_base32()

class ModernPasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.pm = PasswordManager()
        self.totp = None
        self.init_ui()
        self.setup_styling()

    def setup_styling(self):
        # Custom widget styling; additional dark theme applied via qdarktheme.load_stylesheet.
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
            }
            QLabel {
                color: #ffffff;
                font-size: 14px;
            }
            QLineEdit {
                padding: 10px;
                border: 2px solid #2979ff;
                border-radius: 8px;
                background-color: #2d2d2d;
                color: white;
                font-size: 14px;
                min-height: 20px;
            }
            QPushButton {
                background-color: #2979ff;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 14px;
                min-width: 120px;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #1565c0;
            }
            QPushButton:pressed {
                background-color: #0d47a1;
            }
            QTreeWidget {
                background-color: #2d2d2d;
                border: 1px solid #3d3d3d;
                border-radius: 8px;
                color: white;
            }
            QTreeWidget::item {
                padding: 8px;
                margin: 2px;
            }
            QTreeWidget::item:selected {
                background-color: #2979ff;
                border-radius: 4px;
            }
            QScrollBar:vertical {
                border: none;
                background-color: #2d2d2d;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #4d4d4d;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #5d5d5d;
            }
        """)

    def init_ui(self):
        self.setWindowTitle("TigerPass")
        # This is the window size, if anyone wants to change it.
        self.setMinimumSize(1000, 800)
        if os.path.exists(self.pm.db_file):
            self.build_email_verification()
        else:
            self.build_first_time_setup()

    def create_modern_button(self, text, on_click=None, accent=False):
        btn = QPushButton(text)
        if accent:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #2979ff;
                    color: white;
                }
                QPushButton:hover {
                    background-color: #1565c0;
                }
            """)
        if on_click:
            btn.clicked.connect(on_click)
        return btn

    def create_modern_input(self, placeholder="", password=False):
        line_edit = QLineEdit()
        line_edit.setPlaceholderText(placeholder)
        if password:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        return line_edit

    def build_first_time_setup(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        header = QLabel("First Time Setup")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(header, alignment=Qt.AlignmentFlag.AlignCenter)
        self.email_input = self.create_modern_input("Enter Email")
        self.master_pass_input = self.create_modern_input("Create Master Password", password=True)
        self.confirm_pass_input = self.create_modern_input("Confirm Master Password", password=True)
        for widget in [self.email_input, self.master_pass_input, self.confirm_pass_input]:
            layout.addWidget(widget)
        setup_btn = self.create_modern_button("Setup Account", self.complete_setup, accent=True)
        layout.addWidget(setup_btn)
        layout.addStretch()

    def build_main_interface(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        header_layout = QHBoxLayout()
        add_btn = self.create_modern_button("Add Entry", self.add_entry_dialog)
        generate_btn = self.create_modern_button("Generate Password", self.show_generated_password)
        header_layout.addWidget(add_btn)
        header_layout.addWidget(generate_btn)
        layout.addLayout(header_layout)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Account", "Username", "Password (Double-click to Reveal)"])
        self.tree.setColumnWidth(0, 200)
        self.tree.setColumnWidth(1, 200)
        self.tree.setColumnWidth(2, 200)
        self.tree.itemDoubleClicked.connect(self.toggle_password_visibility)
        layout.addWidget(self.tree)
        self.update_account_list()

    def toggle_password_visibility(self, item, column):
        if column == 2:
            account = item.text(0)
            entry = self.pm.get_entry(account)
            if item.text(2) == '••••••••':
                item.setText(2, entry['password'])
            else:
                item.setText(2, '••••••••')

    def update_account_list(self):
        self.tree.clear()
        for account in self.pm.get_all_accounts():
            entry = self.pm.get_entry(account)
            if entry:
                item = QTreeWidgetItem([account, entry['username'], '••••••••'])
                self.tree.addTopLevelItem(item)

    def add_entry_dialog(self):
        account, ok = QInputDialog.getText(self, 'Add Entry', 'Enter Account Name:', QLineEdit.EchoMode.Normal)
        if ok and account:
            username, ok = QInputDialog.getText(self, 'Add Entry', 'Enter Username:', QLineEdit.EchoMode.Normal)
            if ok and username:
                msg_box = QMessageBox()
                msg_box.setWindowTitle("Password Options")
                msg_box.setText("Would you like to generate a secure random password?")
                msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                msg_box.setDefaultButton(QMessageBox.StandardButton.Yes)
                if msg_box.exec() == QMessageBox.StandardButton.Yes:
                    password = generate_password()
                else:
                    password, ok = QInputDialog.getText(self, 'Add Entry', 'Enter Password:', QLineEdit.EchoMode.Password)
                    if not ok or not password:
                        return
                self.pm.add_entry(account, username, password)
                self.update_account_list()
                QMessageBox.information(self, 'Success', f"Entry for '{account}' added successfully.")

    def show_generated_password(self):
        password = generate_password()
        msg = QMessageBox(self)
        msg.setWindowTitle("Generated Password")
        msg.setText("Your secure password:")
        msg.setInformativeText(password)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def verify_login(self):
        master_password = self.master_pass_input.text().strip()
        code = self.totp_input.text().strip()
        if not self.totp.verify(code):
            QMessageBox.critical(self, "Error", "Invalid 2FA Code")
            return
        self.pm.master_password = master_password
        try:
            if not self.pm.load_data():
                QMessageBox.critical(self, "Error", "Invalid master password!")
                return
        except Exception as e:
            QMessageBox.critical(self, "Error", "Invalid master password!")
            return
        self.build_main_interface()

    def complete_setup(self):
        email = self.email_input.text().strip()
        password = self.master_pass_input.text()
        confirm = self.confirm_pass_input.text()
        if not email or '@' not in email:
            QMessageBox.critical(self, "Error", "Please enter a valid email address.")
            return
        if password != confirm:
            QMessageBox.critical(self, "Error", "Passwords do not match!")
            return
        if len(password) < 8:
            QMessageBox.critical(self, "Error", "Password must be at least 8 characters long!")
            return
        self.pm.initialize(email, password)
        # Generate and persist the OTP secret during first-time setup.
        secret = generate_2fa_secret()
        self.pm.otp_secret = secret
        self.pm.save_data()
        self.totp = pyotp.TOTP(secret)
        self.build_2fa_setup(email, secret)

    def build_2fa_setup(self, email, secret):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        header = QLabel("2FA Setup")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(header, alignment=Qt.AlignmentFlag.AlignCenter)
        uri = self.totp.provisioning_uri(name=email, issuer_name="TigerPass")
        qr = qrcode.QRCode(box_size=10, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_pixmap = QPixmap.fromImage(qr_image.toqimage())
        qr_label = QLabel()
        qr_label.setPixmap(qr_pixmap)
        qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(qr_label)
        instructions = QLabel("Scan this QR code with your\n2FA app (e.g. Google Authenticator)")
        instructions.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(instructions)
        self.verify_2fa_input = self.create_modern_input("Enter the 2FA Code from Your Authenticator App Here.")
        layout.addWidget(self.verify_2fa_input)
        verify_btn = self.create_modern_button("Complete Setup", self.verify_2fa_setup, accent=True)
        layout.addWidget(verify_btn)
        layout.addStretch()

    def verify_2fa_setup(self):
        code = self.verify_2fa_input.text().strip()
        if not self.totp.verify(code):
            QMessageBox.critical(self, "Error", "Invalid 2FA Code")
            return
        self.build_main_interface()

    def build_email_verification(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        header = QLabel("Email Verification")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(header, alignment=Qt.AlignmentFlag.AlignCenter)
        self.email_input = self.create_modern_input("Enter Email")
        layout.addWidget(self.email_input)
        continue_btn = self.create_modern_button("Continue", self.verify_email, accent=True)
        layout.addWidget(continue_btn)
        layout.addStretch()

    def verify_email(self):
        email = self.email_input.text().strip()
        with open(self.pm.db_file, "r") as f:
            content = json.load(f)
        stored_email = content.get("email")
        otp_secret = content.get("otp_secret")
        if email != stored_email:
            QMessageBox.critical(self, "Error", "Email not recognized!")
            return
        if not otp_secret:
            QMessageBox.critical(self, "Error", "OTP Configuration Missing!")
            return
        self.pm.otp_secret = otp_secret
        self.totp = pyotp.TOTP(otp_secret)
        self.build_login_interface()

    def build_login_interface(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        header = QLabel("Login")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        layout.addWidget(header, alignment=Qt.AlignmentFlag.AlignCenter)
        self.master_pass_input = self.create_modern_input("Enter Master Password", password=True)
        self.totp_input = self.create_modern_input("Enter 2FA Code")
        layout.addWidget(self.master_pass_input)
        layout.addWidget(self.totp_input)
        login_btn = self.create_modern_button("Login", self.verify_login, accent=True)
        layout.addWidget(login_btn)
        layout.addStretch()

def main():
    app = QApplication(sys.argv)
    # Apply the dark theme using qdarktheme's load_stylesheet function.
    app.setStyleSheet(qdarktheme.load_stylesheet())
    QFontDatabase.addApplicationFont(":/fonts/Roboto-Regular.ttf")
    app.setFont(QFont("Roboto", 10))
    window = ModernPasswordManagerGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
