from flask import session, g
import pyotp
from werkzeug.security import check_password_hash
from storage import load_users
from encryption import derive_key
import base64

FAILED_LOGINS = {}

def record_failed_attempt(username):
    if username not in FAILED_LOGINS:
        FAILED_LOGINS[username] = {'attempts': 0}
    FAILED_LOGINS[username]['attempts'] += 1

def is_user_blocked(username):
    if username in FAILED_LOGINS and FAILED_LOGINS[username]['attempts'] >= 3:
        return True, 60
    return False, 0

def clear_failed_attempts(username):
    if username in FAILED_LOGINS:
        del FAILED_LOGINS[username]

def setup_mfa_qr(username):
    users = load_users()
    user_data = users.get(username)
    
    if not user_data:
        return None, None
    
    totp = pyotp.TOTP(user_data['mfa_secret'])
    uri = totp.provisioning_uri(username, issuer_name="Password Manager")
    
    return uri, user_data['mfa_secret']

def verify_login(username, password, mfa_code):
    users = load_users()
    user_data = users.get(username)
    
    if not user_data:
        return False, "Invalid username or password"
    
    if not check_password_hash(user_data['password_hash'], password):
        return False, "Invalid username or password"
    
    totp = pyotp.TOTP(user_data['mfa_secret'])
    if not totp.verify(mfa_code):
        return False, "Invalid MFA code"
    
    return True, "Success"

def setup_session(username, password):
    """Тепер зберігаємо тільки salt, не ключ!"""
    users = load_users()
    user_data = users.get(username)
    
    if not user_data:
        return False
        
    session.clear()
    session["username"] = username
    session["user_salt"] = user_data['encryption_salt']  # Тільки salt!
    session["authenticated"] = True
    session.permanent = True
    
    # Тимчасово зберігаємо пароль в контексті запиту
    g.master_password = password
    return True

def get_encryption_key():
    """Отримуємо ключ на льоту"""
    if not session.get("authenticated") or not session.get("username"):
        return None
        
    salt_b64 = session.get("user_salt")
    if not salt_b64:
        return None
        
    # Отримуємо пароль з контексту
    master_password = getattr(g, 'master_password', None)
    if not master_password:
        return None
        
    try:
        salt = base64.b64decode(salt_b64)
        encryption_key, _ = derive_key(master_password, salt)
        return encryption_key
    except Exception:
        return None

def validate_session():
    """Перевіряємо валідність сесії"""
    return session.get("authenticated", False)
