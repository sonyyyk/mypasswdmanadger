import json
import os
import base64
import pyotp
from werkzeug.security import generate_password_hash

USERS_FILE = "users.json"
PASSWORDS_FILE = "passwords.json"

def load_users():
    """Load all users from JSON file"""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}
    return {}

def save_users(users):
    """Save users to JSON file with atomic write"""
    try:
        tmp = USERS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        os.replace(tmp, USERS_FILE)
        print("✅ Users saved successfully")
    except Exception as e:
        print(f"❌ Error saving users: {e}")

def load_user_passwords(username):
    """Load encrypted passwords for specific user"""
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
    """Save encrypted passwords for specific user"""
    try:
        # Load all data
        all_data = {}
        if os.path.exists(PASSWORDS_FILE):
            with open(PASSWORDS_FILE, "r", encoding="utf-8") as f:
                all_data = json.load(f)
        
        # Update specific user's data
        all_data[username] = passwords_data
        
        # Atomic write to temporary file
        tmp = PASSWORDS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
        
        # Replace original file
        os.replace(tmp, PASSWORDS_FILE)
        print(f"✅ Passwords saved for user: {username}")
        
    except Exception as e:
        print(f"❌ Error saving passwords for {username}: {e}")

def upgrade_user_format():
    """Upgrade old user format to new format with MFA"""
    users = load_users()
    changed = False
    
    for username, value in users.items():
        # If old format (just password hash string)
        if isinstance(value, str):
            users[username] = {
                'password_hash': value,
                'mfa_secret': pyotp.random_base32()
            }
            changed = True
    
    if changed:
        save_users(users)
        print("✅ User format upgraded")

def create_user(username, password):
    """Create new user with password hash, MFA secret and encryption salt"""
    users = load_users()
    
    # Generate encryption salt and key
    from encryption import derive_key
    encryption_key, salt = derive_key(password)
    
    users[username] = {
        'password_hash': generate_password_hash(password),
        'mfa_secret': pyotp.random_base32(),
        'encryption_salt': base64.b64encode(salt).decode('utf-8')  # Store salt for consistent key derivation
    }
    save_users(users)
    print(f"✅ User {username} created successfully")

def get_user_salt(username):
    """Get encryption salt for user"""
    users = load_users()
    user_data = users.get(username, {})
    salt_b64 = user_data.get('encryption_salt')
    if salt_b64:
        return base64.b64decode(salt_b64)
    return None

def get_user_mfa_secret(username):
    """Get MFA secret for user"""
    users = load_users()
    user_data = users.get(username, {})
    return user_data.get('mfa_secret')

def migrate_existing_users():
    """Add encryption salt for existing users who don't have it"""
    users = load_users()
    changed = False
    
    for username, user_data in users.items():
        if isinstance(user_data, dict) and 'encryption_salt' not in user_data:
            # Generate random salt for existing users
            import os
            salt = os.urandom(16)
            user_data['encryption_salt'] = base64.b64encode(salt).decode('utf-8')
            changed = True
    
    if changed:
        save_users(users)
        print("✅ Added salt for existing users")

def user_exists(username):
    """Check if user exists"""
    users = load_users()
    return username in users

def get_user_data(username):
    """Get complete user data"""
    users = load_users()
    return users.get(username)

def delete_user_passwords(username):
    """Delete all passwords for user (account deletion)"""
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
