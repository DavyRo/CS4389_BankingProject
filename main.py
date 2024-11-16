import tkinter as tk
from tkinter import messagebox
import sqlite3
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import random
import logging
import smtplib
from email.mime.text import MIMEText
import re
from pathlib import Path
from datetime import datetime, timedelta

# Configure Logging
downloads = str(Path.home() / "Downloads")
log_file = os.path.join(downloads, 'log.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# SMTP Settings
smtp_server = 'smtp.gmail.com'
smtp_port = 587
sender_email = 'Dhevvijay2457@gmail.com'
sender_password = 'islr maki xohj loxj'

# Initialize Password Hasher
password_hasher = PasswordHasher()

# Encryption Key Management
def load_or_create_key():
    key_path = "secret.key"
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            return key_file.read()
    else:
        key = AESGCM.generate_key(bit_length=128)
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        return key

encryption_key = load_or_create_key()
aes_cipher = AESGCM(encryption_key)

# Database Setup
db_connection = sqlite3.connect('database.db')
db_cursor = db_connection.cursor()

db_cursor.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        password_hash TEXT,
        email TEXT UNIQUE,
        balance REAL,
        encrypted_data BLOB,
        nonce BLOB,
        failed_attempts INTEGER DEFAULT 0,
        lockout_time TEXT
    )
''')
db_connection.commit()

# Ensure All Required Columns Exist
def ensure_columns():
    db_cursor.execute("PRAGMA table_info(accounts)")
    existing_cols = {col[1] for col in db_cursor.fetchall()}
    required_cols = {'id', 'name', 'password_hash', 'email', 'balance', 'encrypted_data', 'nonce', 'failed_attempts', 'lockout_time'}
    missing = required_cols - existing_cols

    for col in missing:
        if col == 'failed_attempts':
            db_cursor.execute("ALTER TABLE accounts ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        elif col == 'lockout_time':
            db_cursor.execute("ALTER TABLE accounts ADD COLUMN lockout_time TEXT")
        elif col == 'nonce':
            db_cursor.execute("ALTER TABLE accounts ADD COLUMN nonce BLOB")
        elif col == 'email':
            db_cursor.execute("ALTER TABLE accounts ADD COLUMN email TEXT UNIQUE")
    db_connection.commit()

ensure_columns()

# Verify Database Schema
def verify_schema():
    db_cursor.execute("PRAGMA table_info(accounts)")
    columns = db_cursor.fetchall()
    schema_ok = True
    for col in columns:
        name, type_ = col[1], col[2].upper()
        if name == 'id' and 'INTEGER' not in type_:
            schema_ok = False
        elif name in {'name', 'password_hash', 'email'} and 'TEXT' not in type_:
            schema_ok = False
        elif name == 'balance' and 'REAL' not in type_:
            schema_ok = False
        elif name in {'encrypted_data', 'nonce'} and 'BLOB' not in type_:
            schema_ok = False
        elif name == 'failed_attempts' and 'INTEGER' not in type_:
            schema_ok = False
        elif name == 'lockout_time' and 'TEXT' not in type_:
            schema_ok = False
    if schema_ok:
        logging.info("Database schema verified successfully.")
    else:
        logging.error("Database schema verification failed.")

verify_schema()

# Account Class
class Account:
    def __init__(self, name, phash, email, balance=0.0):
        self.name = name
        self.phash = phash
        self.email = email
        self.balance = balance

    def check_password(self, password):
        try:
            password_hasher.verify(self.phash, password)
            return True
        except:
            return False

    def deposit(self, amount):
        if amount > 0:
            if amount > 2000:
                if not self.verify_transaction():
                    messagebox.showwarning("Error:", "Verification failed.")
                    logging.warning(f"{self.name} failed deposit verification of ${amount:.2f}")
                    return
            self.balance += amount
            messagebox.showinfo("Success", f"Deposited ${amount:.2f}")
            logging.info(f"{self.name} deposited ${amount:.2f}")
        else:
            messagebox.showwarning("Error:", "Positive deposit required.")

    def withdraw(self, amount):
        if 0 < amount <= self.balance:
            if amount > 2000:
                if not self.verify_transaction():
                    messagebox.showwarning("Error:", "Verification failed.")
                    logging.warning(f"{self.name} failed withdrawal verification of ${amount:.2f}")
                    return
            self.balance -= amount
            messagebox.showinfo("Success", f"Withdrew ${amount:.2f}")
            logging.info(f"{self.name} withdrew ${amount:.2f}")
        else:
            messagebox.showwarning("Error:", "Insufficient funds.")

    def show_balance(self):
        messagebox.showinfo("Balance", f"Current balance: ${self.balance:.2f}")
        return self.balance

    def verify_transaction(self):
        otp = send_otp(self.email)
        if not otp:
            return False
        otp_win = tk.Toplevel()
        otp_win.title("Verification")
        otp_win.geometry("300x150")
        otp_win.configure(bg="#2C2C2C")

        prompt = tk.Label(otp_win, text="Enter OTP sent to your email:", bg="#2C2C2C", fg="#FFFFFF", font=("Times New Roman", 12))
        prompt.pack(pady=10)
        otp_entry = tk.Entry(otp_win, font=("Times New Roman", 12))
        otp_entry.pack(pady=5)

        verified = {'status': False}

        def verify_otp():
            entered = otp_entry.get()
            if otp and str(otp) == entered:
                messagebox.showinfo("Success", "Verified.")
                otp_win.destroy()
                verified['status'] = True
            else:
                messagebox.showwarning("Error:", "Invalid OTP.")
                otp_win.destroy()

        verify_btn = tk.Button(otp_win, text="Verify", command=verify_otp, bg="#555555", fg="white",
                               font=("Times New Roman", 12, "bold"), relief="raised", bd=2)
        verify_btn.pack(pady=10)
        otp_win.wait_window()
        return verified['status']

# Encryption Functions
def encrypt_account(account):
    try:
        data = json.dumps(account.__dict__).encode()
        nonce = os.urandom(12)
        encrypted = aes_cipher.encrypt(nonce, data, None)
        return encrypted, nonce
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return None, None

def decrypt_account(encrypted_data, nonce):
    if not nonce or not isinstance(nonce, bytes) or len(nonce) != 12:
        logging.error("Invalid nonce for decryption.")
        return None
    try:
        decrypted = aes_cipher.decrypt(nonce, encrypted_data, None)
        data = json.loads(decrypted.decode())
        return Account(**data)
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return None

# OTP Generation and Sending
def send_otp(email_address):
    otp = random.randint(100000, 999999)
    try:
        msg = MIMEText(f"Your OTP is {otp}")
        msg['Subject'] = 'Your OTP Code'
        msg['From'] = sender_email
        msg['To'] = email_address

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        logging.info(f"OTP sent to {email_address}")
    except Exception as e:
        logging.error(f"Failed to send OTP to {email_address}: {e}")
        messagebox.showwarning("Error:", "Failed to send OTP.")
        return None
    return otp

# Email Validation
def is_valid_email(email):
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(pattern, email) is not None

# Password Strength Checker
def check_password_strength(password):
    if len(password) < 8:
        return False, "Error: Min 8 chars."
    if not re.search(r"[A-Z]", password):
        return False, "Error: One uppercase."
    if not re.search(r"[a-z]", password):
        return False, "Error: One lowercase."
    if not re.search(r"\d", password):
        return False, "Error: One digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Error: One special char."
    return True, ""

# Main Application Class
class BankingApp:
    def __init__(self, master):
        self.master = master
        master.title("DAS Banking")
        master.geometry("600x500")
        master.configure(bg="#1A1A1A")
        self.setup_main_menu()

    def setup_main_menu(self):
        self.clear_window()
        main_frame = tk.Frame(self.master, bg="#1A1A1A")
        main_frame.pack(expand=True)

        welcome = tk.Label(main_frame, text="Welcome to DAS Banking", font=("Times New Roman", 24, "bold"),
                           bg="#1A1A1A", fg="#FFFFFF")
        welcome.pack(pady=40)

        create_btn = tk.Button(main_frame, text="Create Account", command=self.create_account_ui, width=25,
                               bg="#333333", fg="white", font=("Times New Roman", 14, "bold"),
                               relief="raised", bd=3, activebackground="#4D4D4D")
        create_btn.pack(pady=20)

        login_btn = tk.Button(main_frame, text="Login to Account", command=self.login_ui, width=25,
                              bg="#4D4D4D", fg="white", font=("Times New Roman", 14, "bold"),
                              relief="raised", bd=3, activebackground="#666666")
        login_btn.pack(pady=20)

        exit_btn = tk.Button(main_frame, text="Exit", command=self.master.quit, width=25,
                             bg="#666666", fg="white", font=("Times New Roman", 14, "bold"),
                             relief="raised", bd=3, activebackground="#808080")
        exit_btn.pack(pady=20)

    # Account Creation UI
    def create_account_ui(self):
        self.clear_window()
        create_frame = tk.Frame(self.master, bg="#333333")
        create_frame.pack(expand=True)

        title = tk.Label(create_frame, text="Create Account", font=("Times New Roman", 20, "bold"),
                         bg="#333333", fg="#FFFFFF")
        title.pack(pady=30)

        # Name
        name_lbl = tk.Label(create_frame, text="Name:", bg="#333333", fg="#FFFFFF", font=("Times New Roman", 14))
        name_lbl.pack(pady=5)
        name_ent = tk.Entry(create_frame, width=40, font=("Times New Roman", 14))
        name_ent.pack(pady=5)

        # Password
        pwd_lbl = tk.Label(create_frame, text="Password:", bg="#333333", fg="#FFFFFF", font=("Times New Roman", 14))
        pwd_lbl.pack(pady=5)
        pwd_ent = tk.Entry(create_frame, show="*", width=40, font=("Times New Roman", 14))
        pwd_ent.pack(pady=5)

        # Email
        email_lbl = tk.Label(create_frame, text="Email Address:", bg="#333333", fg="#FFFFFF", font=("Times New Roman", 14))
        email_lbl.pack(pady=5)
        email_ent = tk.Entry(create_frame, width=40, font=("Times New Roman", 14))
        email_ent.pack(pady=5)

        # Initial Balance
        bal_lbl = tk.Label(create_frame, text="Initial Balance:", bg="#333333", fg="#FFFFFF", font=("Times New Roman", 14))
        bal_lbl.pack(pady=5)
        bal_ent = tk.Entry(create_frame, width=40, font=("Times New Roman", 14))
        bal_ent.pack(pady=5)

        # Create Account Action
        def create_account():
            name = name_ent.get().strip()
            email = email_ent.get().strip().lower()  # Normalize to lowercase
            password = pwd_ent.get()
            balance_str = bal_ent.get()

            try:
                balance = float(balance_str)
            except ValueError:
                messagebox.showwarning("Error:", "Error: Invalid balance.")
                return

            if not name or not email or not password:
                messagebox.showwarning("Error:", "Error: All fields required.")
                return

            if not is_valid_email(email):
                messagebox.showwarning("Error:", "Error: Invalid email format.")
                return

            db_cursor.execute("SELECT email FROM accounts WHERE email = ?", (email,))
            if db_cursor.fetchone():
                messagebox.showwarning("Error:", "Error: Email exists.")
                return

            valid, msg = check_password_strength(password)
            if not valid:
                messagebox.showwarning("Error:", msg)
                pwd_ent.delete(0, tk.END)
                return

            try:
                pwd_hash = password_hasher.hash(password)
            except Exception as e:
                logging.error(f"Hashing failed: {e}")
                messagebox.showwarning("Error:", "Error: Hashing failed.")
                return

            account = Account(name, pwd_hash, email, balance)
            enc_data, nonce = encrypt_account(account)
            if not enc_data or not nonce:
                messagebox.showwarning("Error:", "Error: Encryption failed.")
                return

            try:
                db_cursor.execute("""INSERT INTO accounts 
                                     (name, password_hash, email, balance, encrypted_data, nonce, failed_attempts, lockout_time) 
                                     VALUES (?, ?, ?, ?, ?, ?, 0, NULL)""",
                                   (name, pwd_hash, email, balance, enc_data, nonce))
                db_connection.commit()
                logging.info(f"Account created: {email}")
            except sqlite3.Error as e:
                logging.error(f"DB Insert failed: {e}")
                messagebox.showwarning("Error:", "Error: Account creation failed.")
                return

            messagebox.showinfo("Success", "Account created.")
            self.setup_main_menu()

        # Create and Back Buttons
        create_btn = tk.Button(create_frame, text="Create", command=create_account, width=20,
                               bg="#333333", fg="white", font=("Times New Roman", 14, "bold"),
                               relief="raised", bd=3, activebackground="#555555")
        create_btn.pack(pady=20)

        back_btn = tk.Button(create_frame, text="Back", command=lambda: self.setup_main_menu(),
                             width=20, bg="#808080", fg="white", font=("Times New Roman", 14, "bold"),
                             relief="raised", bd=3, activebackground="#999999")
        back_btn.pack(pady=10)

    # Login UI
    def login_ui(self):
        self.clear_window()
        login_frame = tk.Frame(self.master, bg="#4D4D4D")
        login_frame.pack(expand=True)

        title = tk.Label(login_frame, text="Login to Account", font=("Times New Roman", 20, "bold"),
                         bg="#4D4D4D", fg="#FFFFFF")
        title.pack(pady=30)

        # Email
        email_lbl = tk.Label(login_frame, text="Email Address:", bg="#4D4D4D", fg="#FFFFFF", font=("Times New Roman", 14))
        email_lbl.pack(pady=5)
        email_ent = tk.Entry(login_frame, width=40, font=("Times New Roman", 14))
        email_ent.pack(pady=5)

        # Password
        pwd_lbl = tk.Label(login_frame, text="Password:", bg="#4D4D4D", fg="#FFFFFF", font=("Times New Roman", 14))
        pwd_lbl.pack(pady=5)
        pwd_ent = tk.Entry(login_frame, show="*", width=40, font=("Times New Roman", 14))
        pwd_ent.pack(pady=5)

        # Login Action
        def perform_login():
            email = email_ent.get().strip().lower()  # Normalize to lowercase
            password = pwd_ent.get()

            if not email or not password:
                messagebox.showwarning("Error:", "Error: All fields required.")
                return

            db_cursor.execute("""SELECT password_hash, name, encrypted_data, nonce, failed_attempts, lockout_time 
                                 FROM accounts WHERE email = ?""", (email,))
            record = db_cursor.fetchone()

            if not record:
                messagebox.showwarning("Error:", "Error: Account not found.")
                return

            pwd_hash, name, enc_data, nonce, failed_attempts, lockout_time = record
            account = decrypt_account(enc_data, nonce)

            if not account:
                messagebox.showwarning("Error:", "Error: Decryption failed.")
                return

            if account.check_password(password):
                if failed_attempts >= 5:
                    try:
                        lock_time = datetime.strptime(lockout_time, "%Y-%m-%d %H:%M:%S.%f")
                    except ValueError:
                        lock_time = datetime.strptime(lockout_time, "%Y-%m-%d %H:%M:%S")
                    if datetime.now() < lock_time + timedelta(minutes=2):
                        messagebox.showwarning("Error:", "Error: Account locked.")
                        logging.warning(f"Locked account login attempt: {email}")
                        return
                    else:
                        db_cursor.execute("UPDATE accounts SET failed_attempts = 0, lockout_time = NULL WHERE email = ?", (email,))
                        db_connection.commit()

                otp = send_otp(email)
                if not otp:
                    return

                otp_window = tk.Toplevel()
                otp_window.title("OTP Verification")
                otp_window.geometry("300x150")
                otp_window.configure(bg="#333333")

                prompt = tk.Label(otp_window, text="Enter OTP:", bg="#333333", fg="#FFFFFF", font=("Times New Roman", 12))
                prompt.pack(pady=10)
                otp_ent = tk.Entry(otp_window, font=("Times New Roman", 12))
                otp_ent.pack(pady=5)

                def verify_otp():
                    entered = otp_ent.get()
                    if otp and str(otp) == entered:
                        messagebox.showinfo("Success", "Logged in.")
                        otp_window.destroy()
                        self.account_dashboard(account)
                        logging.info(f"Logged in: {email}")
                    else:
                        messagebox.showwarning("Error:", "Error: Invalid OTP.")
                        otp_window.destroy()
                        logging.warning(f"Invalid OTP attempt for: {email}")

                verify_btn = tk.Button(otp_window, text="Verify", command=verify_otp, bg="#333333", fg="white",
                                       font=("Times New Roman", 12, "bold"), relief="raised", bd=2)
                verify_btn.pack(pady=10)
            else:
                failed_attempts += 1
                if failed_attempts >= 5:
                    lock_time = datetime.now()
                    db_cursor.execute("UPDATE accounts SET failed_attempts = ?, lockout_time = ? WHERE email = ?",
                                      (failed_attempts, str(lock_time), email))
                    db_connection.commit()
                    messagebox.showwarning("Error:", "Error: Account locked.")
                    logging.warning(f"Account locked: {email}")
                else:
                    db_cursor.execute("UPDATE accounts SET failed_attempts = ? WHERE email = ?", (failed_attempts, email))
                    db_connection.commit()
                    attempts_left = 5 - failed_attempts
                    messagebox.showwarning("Error:", f"Error: Incorrect password. {attempts_left} left.")
                    logging.info(f"Failed login attempt {failed_attempts} for: {email}")

        # Login and Back Buttons
        login_btn = tk.Button(login_frame, text="Login", command=perform_login, width=25,
                              bg="#1ABC9C", fg="white", font=("Times New Roman", 14, "bold"),
                              relief="raised", bd=3, activebackground="#16A085")
        login_btn.pack(pady=20)

        back_btn = tk.Button(login_frame, text="Back", command=lambda: self.setup_main_menu(),
                             width=25, bg="#808080", fg="white", font=("Times New Roman", 14, "bold"),
                             relief="raised", bd=3, activebackground="#999999")
        back_btn.pack(pady=10)

    # Account Dashboard
    def account_dashboard(self, account):
        self.clear_window()
        dashboard = tk.Frame(self.master, bg="#2C2C2C")
        dashboard.pack(expand=True)

        welcome = tk.Label(dashboard, text=f"Welcome, {account.name}", font=("Times New Roman", 20, "bold"),
                           bg="#2C2C2C", fg="#FFFFFF")
        welcome.pack(pady=30)

        # Deposit Button
        dep_btn = tk.Button(dashboard, text="Deposit", command=lambda: self.deposit_ui(account),
                            width=20, bg="#4D4D4D", fg="white", font=("Times New Roman", 14, "bold"),
                            relief="raised", bd=3, activebackground="#666666")
        dep_btn.pack(pady=15)

        # Withdraw Button
        wit_btn = tk.Button(dashboard, text="Withdraw", command=lambda: self.withdraw_ui(account),
                            width=20, bg="#666666", fg="white", font=("Times New Roman", 14, "bold"),
                            relief="raised", bd=3, activebackground="#808080")
        wit_btn.pack(pady=15)

        # Check Balance Button
        bal_btn = tk.Button(dashboard, text="Check Balance", command=account.show_balance,
                            width=20, bg="#4D4D4D", fg="white", font=("Times New Roman", 14, "bold"),
                            relief="raised", bd=3, activebackground="#666666")
        bal_btn.pack(pady=15)

        # Logout Button
        log_btn = tk.Button(dashboard, text="Logout", command=lambda: self.logout(account),
                            width=20, bg="#808080", fg="white", font=("Times New Roman", 14, "bold"),
                            relief="raised", bd=3, activebackground="#999999")
        log_btn.pack(pady=15)

    # Deposit UI
    def deposit_ui(self, account):
        dep_win = tk.Toplevel(self.master)
        dep_win.title("Deposit")
        dep_win.geometry("400x250")
        dep_win.configure(bg="#4D4D4D")
        dep_frame = tk.Frame(dep_win, bg="#4D4D4D")
        dep_frame.pack(expand=True)

        amt_lbl = tk.Label(dep_frame, text="Amount:", bg="#4D4D4D", fg="#FFFFFF", font=("Times New Roman", 14))
        amt_lbl.pack(pady=20)
        amt_ent = tk.Entry(dep_frame, width=30, font=("Times New Roman", 14))
        amt_ent.pack(pady=5)

        def add_deposit():
            amt_str = amt_ent.get()
            try:
                amt = float(amt_str)
                account.deposit(amt)
                self.update_account(account)
                dep_win.destroy()
            except ValueError:
                messagebox.showwarning("Error:", "Error: Invalid amount.")

        dep_btn = tk.Button(dep_frame, text="Deposit", command=add_deposit, width=15,
                            bg="#1ABC9C", fg="white", font=("Times New Roman", 14, "bold"),
                            relief="raised", bd=3, activebackground="#16A085")
        dep_btn.pack(pady=20)

    # Withdraw UI
    def withdraw_ui(self, account):
        wit_win = tk.Toplevel(self.master)
        wit_win.title("Withdraw")
        wit_win.geometry("400x250")
        wit_win.configure(bg="#666666")
        wit_frame = tk.Frame(wit_win, bg="#666666")
        wit_frame.pack(expand=True)

        amt_lbl = tk.Label(wit_frame, text="Amount:", bg="#666666", fg="#FFFFFF", font=("Times New Roman", 14))
        amt_lbl.pack(pady=20)
        amt_ent = tk.Entry(wit_frame, width=30, font=("Times New Roman", 14))
        amt_ent.pack(pady=5)

        def process_withdraw():
            amt_str = amt_ent.get()
            try:
                amt = float(amt_str)
                account.withdraw(amt)
                self.update_account(account)
                wit_win.destroy()
            except ValueError:
                messagebox.showwarning("Error:", "Error: Invalid amount.")

        wit_btn = tk.Button(wit_frame, text="Withdraw", command=process_withdraw, width=15,
                            bg="#2ECC71", fg="white", font=("Times New Roman", 14, "bold"),
                            relief="raised", bd=3, activebackground="#27AE60")
        wit_btn.pack(pady=20)

    # Logout Function
    def logout(self, account):
        self.update_account(account)
        messagebox.showinfo("Logout", "Logged out.")
        logging.info(f"Logged out: {account.email}")
        self.setup_main_menu()

    # Update Account in Database
    def update_account(self, account):
        enc_data, nonce = encrypt_account(account)
        if not enc_data or not nonce:
            messagebox.showwarning("Error:", "Error: Encryption failed.")
            return
        try:
            db_cursor.execute("""UPDATE accounts SET balance = ?, encrypted_data = ?, nonce = ? WHERE email = ?""",
                              (account.balance, enc_data, nonce, account.email))
            db_connection.commit()
            logging.info(f"Updated account: {account.email}")
        except sqlite3.Error as e:
            logging.error(f"Update failed for {account.email}: {e}")
            messagebox.showwarning("Error:", "Error: Update failed.")

    # Clear Window Function
    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

# Main Function
def main():
    root = tk.Tk()
    app = BankingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
