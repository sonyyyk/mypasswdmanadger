from flask import flash, session
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
from storage import load_users, save_users, get_user_salt, get_user_mfa_secret
from encryption import derive_key
from werkzeug.security import check_password_hash

FAILED_LOGINS = {}

def record_failed_attempt(username):
    """Record failed login attempt"""
    if username not in FAILED_LOGINS:
        FAILED_LOGINS[username] = {
            'attempts': 0,
            'last_attempt': datetime.now(),
            'blocked_until': None
        }
    
    FAILED_LOGINS[username]['attempts'] += 1
    FAILED_LOGINS[username]['last_attempt'] = datetime.now()
    
    if FAILED_LOGINS[username]['attempts'] >= 3:
        FAILED_LOGINS[username]['blocked_until'] = datetime.now() + timedelta(seconds=60)

def is_user_blocked(username):
    """Check if user is temporarily blocked"""
    if username in FAILED_LOGINS:
        failed_data = FAILED_LOGINS[username]
        if failed_data.get('blocked_until') and datetime.now() < failed_data['blocked_until']:
            remaining = int((failed_data['blocked_until'] - datetime.now()).total_seconds())
            return True, remaining
        elif failed_data.get('blocked_until') and datetime.now() >= failed_data['blocked_until']:
            del FAILED_LOGINS[username]
    return False, 0

def clear_failed_attempts(username):
    """Clear failed attempts on successful login"""
    if username in FAILED_LOGINS:
        del FAILED_LOGINS[username]

def setup_mfa_qr(username):
    """Generate QR code for MFA setup"""
    users = load_users()
    user_data = users.get(username)
    
    if not user_data:
        return None, None
    
    totp = pyotp.TOTP(user_data['mfa_secret'])
    uri = totp.provisioning_uri(username, issuer_name="Password Manager")
    
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode()
    
    return qr_code, user_data['mfa_secret']

def verify_login(username, password, mfa_code):
    """Verify username, password and MFA code"""
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
    """Setup user session after successful login"""
    # Get stored salt for consistent key derivation
    salt = get_user_salt(username)
    
    if not salt:
        # Fallback for users without salt (should not happen after migration)
        import os
        salt = os.urandom(16)
    
    # Generate the same encryption key using stored salt
    encryption_key, _ = derive_key(password, salt)
    
    session["username"] = username
    session["encryption_key"] = base64.b64encode(encryption_key).decode('utf-8')