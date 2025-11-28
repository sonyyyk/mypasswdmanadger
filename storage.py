import json
import os
import base64
import pyotp
from werkzeug.security import generate_password_hash

USERS_FILE = "users.json"
PASSWORDS_FILE = "passwords.json"

# ============================
# Users
# ============================
def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}
    return {}

def save_users(users):
    try:
        tmp = USERS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        os.replace(tmp, USERS_FILE)
    except Exception as e:
        print(f"Error saving users: {e}")

def create_user(username, password):
    users = load_users()
    from encryption import derive_key
    encryption_key, salt = derive_key(password)
    users[username] = {
        "password_hash": generate_password_hash(password),
        "mfa_secret": pyotp.random_base32(),
        "encryption_salt": base64.b64encode(salt).decode("utf-8")
    }
    save_users(users)

def user_exists(username):
    users = load_users()
    return username in users

def get_user_data(username):
    users = load_users()
    return users.get(username)

# ============================
# Encryption helpers
# ============================
def get_user_salt(username):
    users = load_users()
    user_data = users.get(username, {})
    salt_b64 = user_data.get("encryption_salt")
    if salt_b64:
        return base64.b64decode(salt_b64)
    return None

def get_user_mfa_secret(username):
    users = load_users()
    data = users.get(username, {})
    return data.get("mfa_secret")

# ============================
# Password entries
# ============================
def load_user_passwords(username):
    try:
        if not os.path.exists(PASSWORDS_FILE):
            return {}
        with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
            all_data = json.load(f)
        return all_data.get(username, {})
    except Exception as e:
        print(f"Error loading passwords for {username}: {e}")
        return {}

def save_user_passwords(username, passwords_data):
    try:
        all_data = {}
        if os.path.exists(PASSWORDS_FILE):
            with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
                all_data = json.load(f)
        all_data[username] = passwords_data
        tmp = PASSWORDS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, PASSWORDS_FILE)
    except Exception as e:
        print(f"Error saving passwords for {username}: {e}")

def delete_user_passwords(username):
    try:
        if not os.path.exists(PASSWORDS_FILE):
            return
        with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
            all_data = json.load(f)
        if username in all_data:
            del all_data[username]
            tmp = PASSWORDS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(all_data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, PASSWORDS_FILE)
    except Exception as e:
        print(f"Error deleting passwords for {username}: {e}")

# ============================
# Migration for old users
# ============================
def migrate_existing_users():
    users = load_users()
    changed = False
    for username, data in users.items():
        if isinstance(data, dict) and "encryption_salt" not in data:
            salt = os.urandom(16)
            data["encryption_salt"] = base64.b64encode(salt).decode("utf-8")
            changed = True
    if changed:
        save_users(users)
