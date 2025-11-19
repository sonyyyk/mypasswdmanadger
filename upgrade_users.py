import os, json
from werkzeug.security import generate_password_hash

USERS_FILE = "users.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

def save_users(d):
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_FILE)

users = load_users()
changed = False

new_users = {}
for username, value in users.items():
    if value is None:
        print(f"Removing user with null password: {username}")
        changed = True
        continue
    # if value looks like a hash (contains ':' typical for werkzeug/scrypt/pbkdf2), keep as-is
    if isinstance(value, str) and ":" in value and len(value) > 20:
        new_users[username] = value
        print(f"Keeping hashed user: {username}")
    else:
        # treat as plain password -> create hash
        plain = "" if value is None else str(value)
        new_hash = generate_password_hash(plain)
        new_users[username] = new_hash
        print(f"Upgraded user {username} -> hashed password")
        changed = True

if changed:
    save_users(new_users)
    print("Users file updated.")
else:
    print("No changes needed.")
