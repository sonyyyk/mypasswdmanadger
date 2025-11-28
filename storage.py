import json
import os
import base64
import pyotp
from werkzeug.security import generate_password_hash

USERS_FILE = "users.json"
PASSWORDS_FILE = "passwords.json"

def load_users():
    """Load all users from JSON file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}
    return {}

def save_users(users):
    """Save users to JSON file atomically."""
    try:
        tmp = USERS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        os.replace(tmp, USERS_FILE)
        print("✅ Users saved successfully")
    except Exception as e:
        print(f"❌ Error saving users: {e}")

def load_user_passwords(username):
    """Load encrypted passwords for a specific user."""
    try:
        if os.path.exists(PASSWORDS_FILE):
            with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
                all_data = json.load(f)
                return all_data.get(username, {})
        return {}
    except Exception as e:
        print(f"Error loading passwords for {username}: {e}")
        return {}

def save_user_passwords(username, passwords_data):
    """Save encrypted passwords for a specific user atomically."""
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
        print(f"✅ Passwords saved for user: {username}")
    except Exception as e:
        print(f"❌ Error saving passwords for {username}: {e}")

def migrate_existing_users():
    """Upgrade old users to new format with MFA and encryption salt."""
    users = load_users()
    changed = False
    import os, base64

    for username, user_data in users.items():
        if isinstance(user_data, str):
            # Old format: just password hash string
            users[username] = {
                'password_hash': user_data,
                'mfa_secret': pyotp.random_base32(),
                'encryption_salt': base64.b64encode(os.urandom(16)).decode('utf-8')
            }
            changed = True
        elif isinstance(user_data, dict):
            if 'mfa_secret' not in user_data:
                user_data['mfa_secret'] = pyotp.random_base32()
                changed = True
            if 'encryption_salt' not in user_data:
                user_data['encryption_salt'] = base64.b64encode(os.urandom(16)).decode('utf-8')
                changed = True

    if changed:
        save_users(users)
        print("✅ Existing users migrated")

def create_user(username, password):
    """Create a new user with password hash, MFA secret, and encryption salt."""
    from encryption import derive_key
    import base64

    users = load_users()
    encryption_key, salt = derive_key(password)

    users[username] = {
        'password_hash': generate_password_hash(password),
        'mfa_secret': pyotp.random_base32(),
        'encryption_salt': base64.b64encode(salt).decode('utf-8')
    }

    save_users(users)
    print(f"✅ User {username} created successfully")

def get_user_data(username):
    """Get complete user data dictionary."""
    users = load_users()
    return users.get(username)

def user_exists(username):
    """Check if a user exists in the system."""
    users = load_users()
    return username in users

def delete_user_passwords(username):
    """Delete all passwords for a specific user."""
    try:
        if os.path.exists(PASSWORDS_FILE):
            with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
                all_data = json.load(f)
            if username in all_data:
                del all_data[username]
                tmp = PASSWORDS_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(all_data, f, indent=2, ensure_ascii=False)
                os.replace(tmp, PASSWORDS_FILE)
                print(f"✅ Passwords deleted for user: {username}")
    except Exception as e:
        print(f"❌ Error deleting passwords for {username}: {e}")
