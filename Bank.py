import time
import pickle
import hashlib
from cryptography.fernet import Fernet

# Generate or load encryption key
try:
    with open("secret.key", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

cipher = Fernet(key)


class Account:
    def __init__(self, name, password, initial_balance = 0.0):
        self.name = name
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()  # Storing a hashed password
        self.balance = initial_balance

    # Checking if user input the correct password
    def verify_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash

    # Method to deposit money in account
    # Checks if user input a valid amount (positive) as well
    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            print(f"Deposited ${amount:.2f} successfully!")
        else:
            print("Deposit amount must be positive.")

    # Method to withdraw amount
    # Checks if the user has sufficient funds as well
    def withdraw(self, amount):
        if 0 < amount <= self.balance:
            self.balance -= amount
            print(f"Withdrew ${amount:.2f} successfully!")
        else:
            print("Insufficient balance.")

    # Method to get account balance if user wants to check
    def get_balance(self):
        print(f"Current balance: ${self.balance:.2f}")
        return self.balance


# Helper functions
def encrypt_data(data):
    return cipher.encrypt(pickle.dumps(data))


def decrypt_data(encrypted_data):
    return pickle.loads(cipher.decrypt(encrypted_data))


accounts = {}
last_activity_time = time.time()


# Logs current account out if inactive for 5 minutes (value can be changed)
def timeout_check():
    if time.time() - last_activity_time > 300:
        print("Session has timed out due to inactivity.")
        exit()

# Function to create account
def create_account():
    global last_activity_time
    last_activity_time = time.time()
    lowercase = set("abcdefghijklmnopqrstuvwxyz")
    uppercase = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    digits = set("0123456789")
    name = input("Enter account name: ")
    if name in accounts:
        print("Account already exists.")
        return
    valid_password = False
    print("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one digit.")
    while not valid_password:
        password = input("Enter a password: ")
        valid_password = True
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            valid_password = False
        if not any(c in uppercase for c in password):
            print("Password must contain at least one uppercase letter.")
            valid_password = False
        if not any(c in lowercase for c in password):
            print("Password must contain at least one lowercase letter.")
            valid_password = False
        if not any(c in digits for c in password):
            print("Password must contain at least one digit.")
            valid_password = False
    initial_balance = float(input("Enter initial balance: "))
    accounts[name] = encrypt_data(Account(name, password, initial_balance))
    print("Account created successfully.")


# Function to check user credentials when logging into existing account
def login_account():
    global last_activity_time
    last_activity_time = time.time()

    name = input("Enter account name: ")
    if name in accounts:
        account = decrypt_data(accounts[name])

    password = input("Enter your password: ")
    if name not in accounts or not account.verify_password(password):
        print("Invalid account name or password.")
        return

    print("Login successful!")
    while True:
        timeout_check()
        print("\nChoose an option:")
        print("1. Deposit")
        print("2. Withdraw")
        print("3. Check Balance")
        print("4. Log Out")
        choice = input("Enter your choice: ")
        if choice == "1":
            amount = float(input("Enter amount to deposit: "))
            account.deposit(amount)
        elif choice == "2":
            amount = float(input("Enter amount to withdraw: "))
            account.withdraw(amount)
        elif choice == "3":
            account.get_balance()
        elif choice == "4":
            accounts[name] = encrypt_data(account)
            print("Exiting account menu.")
            break
        else:
            print("Invalid choice. Please try again.")
        last_activity_time = time.time()


def main():
    while True:
        timeout_check()
        print("\nBanking App Menu:")
        print("1. Create Account")
        print("2. Login to Account")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            create_account()
        elif choice == "2":
            login_account()
        elif choice == "3":
            print("Thank you for using the banking app!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
