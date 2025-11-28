from flask import session, g
import pyotp
from werkzeug.security import check_password_hash
from storage import load_users, save_users, migrate_existing_users
from encryption import derive_key
import base64
import qrcode
from io import BytesIO

FAILED_LOGINS = {}

# ========================
# Security helpers
# ========================
def record_failed_attempt(username):
    """Record a failed login attempt."""
    if username not in FAILED_LOGINS:
        FAILED_LOGINS[username] = {'attempts': 0}
    FAILED_LOGINS[username]['attempts'] += 1


def is_user_blocked(username):
    """Check if the user is blocked due to too many failed attempts."""
    if username in FAILED_LOGINS and FAILED_LOGINS[username]['attempts'] >= 3:
        return True, 60  # blocked for 60 seconds
    return False, 0


def clear_failed_attempts(username):
    """Clear failed login attempts for a user."""
    if username in FAILED_LOGINS:
        del FAILED_LOGINS[username]

# ========================
# MFA helpers
# ========================
def get_or_create_mfa_secret(username):
    """Get existing MFA secret or create a new one."""
    users = load_users()
    user_data = users.get(username)

    if not user_data:
        return None

    if 'mfa_secret' not in user_data or not user_data['mfa_secret']:
        user_data['mfa_secret'] = pyotp.random_base32()
        save_users(users)

    return user_data['mfa_secret']


def setup_mfa_qr(username):
    """Generate QR code PNG (base64) and MFA secret."""
    users = load_users()
    user_data = users.get(username)

    if not user_data:
        return None, None

    # Ensure secret exists
    secret = get_or_create_mfa_secret(username)
    totp = pyotp.TOTP(secret)

    # Create provisioning URI
    uri = totp.provisioning_uri(name=username, issuer_name="Password Manager")

    # Generate QR image
    qr_img = qrcode.make(uri)
    buffer = BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_bytes = buffer.getvalue()

    # Convert to Base64
    qr_base64 = base64.b64encode(qr_bytes).decode("utf-8")

    return qr_base64, secret

# ========================
# Login / Registration
# ========================
def verify_login(username, password, mfa_code):
    """Verify username, password hash, and MFA code."""
    users = load_users()
    user_data = users.get(username)

    if not user_data:
        return False, "Invalid username or password"

    if not check_password_hash(user_data['password_hash'], password):
        return False, "Invalid username or password"

    secret = get_or_create_mfa_secret(username)
    totp = pyotp.TOTP(secret)

    if not totp.verify(mfa_code):
        return False, "Invalid MFA code"

    return True, "Success"


def setup_session(username, password):
    """Setup Flask session with user authentication and salt."""
    users = load_users()
    user_data = users.get(username)

    if not user_data:
        return False

    session.clear()
    session["username"] = username
    session["user_salt"] = user_data['encryption_salt']
    session["authenticated"] = True
    session.permanent = True
    g.master_password = password

    return True


def get_encryption_key():
    """Get encryption key from master password and salt."""
    if not session.get("authenticated") or not session.get("username"):
        return None

    salt_b64 = session.get("user_salt")
    if not salt_b64:
        return None

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
    """Validate if the current session is authenticated."""
    return session.get("authenticated", False)

# ========================
# Initialize on app start
# ========================
migrate_existing_users()
