from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_wtf.csrf import CSRFProtect
import os
import logging
from functools import wraps
import re
import base64
from datetime import datetime, timedelta

# Імпорти з ваших модулів
from auth import verify_login, setup_session, is_user_blocked, clear_failed_attempts, record_failed_attempt, setup_mfa_qr
from storage import load_users, create_user, load_user_passwords, save_user_passwords, upgrade_user_format, migrate_existing_users
from encryption import encrypt_data, decrypt_data

# Налаштування логування
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ініціалізація Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Налаштування сесій
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# CSRF захист
csrf = CSRFProtect(app)

# Допоміжні функції
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in first", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def validate_username(username):
    if not username or not isinstance(username, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def sanitize_text(text):
    if not text:
        return ""
    for char in ['<', '>', '"', "'", '&', '\\', '/', ';']:
        text = text.replace(char, '')
    return text.strip()

# Маршрути
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        mfa_code = request.form.get("mfa_code") or ""

        if not validate_username(username):
            flash("Invalid username format", "error")
            return redirect(url_for("login"))

        blocked, remaining = is_user_blocked(username)
        if blocked:
            flash(f"Too many failed attempts. Try again in {remaining} seconds", "error")
            return redirect(url_for("login"))

        success, message = verify_login(username, password, mfa_code)
        if success:
            clear_failed_attempts(username)
            setup_session(username, password)
            session.permanent = True
            logger.info(f"User logged in: {username}")
            flash("Signed in successfully", "success")
            return redirect(url_for("dashboard"))
        else:
            record_failed_attempt(username)
            flash(message, "error")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        master_password = request.form.get("master_password") or ""
        confirm = request.form.get("confirm") or ""

        if not validate_username(username):
            flash("Username must be 3-20 characters, only letters, numbers and underscore", "error")
            return redirect(url_for("register"))

        if not username or not master_password:
            flash("Fill all fields", "error")
            return redirect(url_for("register"))

        if len(master_password) < 16:
            flash("Password must be at least 16 characters long", "error")
            return redirect(url_for("register"))

        if not any(char.isupper() for char in master_password):
            flash("Password must contain at least one uppercase letter", "error")
            return redirect(url_for("register"))

        if not any(char.islower() for char in master_password):
            flash("Password must contain at least one lowercase letter", "error")
            return redirect(url_for("register"))

        if not any(char.isdigit() for char in master_password):
            flash("Password must contain at least one number", "error")
            return redirect(url_for("register"))

        if master_password != confirm:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        users = load_users()
        if username in users:
            flash("User already exists - add a symbol or change the name", "error")
            return redirect(url_for("register"))

        create_user(username, master_password)
        logger.info(f"New user registered: {username}")
        return redirect(url_for('setup_mfa', username=username))

    return render_template("register.html")

@app.route("/setup_mfa/<username>")
def setup_mfa(username):
    if not validate_username(username):
        flash("Invalid username", "error")
        return redirect(url_for('register'))

    qr_code, mfa_secret = setup_mfa_qr(username)
    if not qr_code:
        flash("User not found", "error")
        return redirect(url_for('register'))

    return render_template("setup_mfa.html", username=username, qr_code=qr_code, mfa_secret=mfa_secret)

@app.route("/dashboard")
@login_required
def dashboard():
    username = session.get("username")
    encryption_key_b64 = session.get("encryption_key")
    
    if not encryption_key_b64:
        flash("Session expired, please log in again", "error")
        return redirect(url_for("logout"))

    try:
        encryption_key = base64.b64decode(encryption_key_b64)
        user_passwords = load_user_passwords(username)

        entries = []
        for entry_id, entry_data in user_passwords.items():
            try:
                decrypted_password = decrypt_data(encryption_key, entry_data['password'])
                decrypted_login = decrypt_data(encryption_key, entry_data['login']) if entry_data.get('login') else ""
                
                entries.append({
                    'id': entry_id,
                    'title': sanitize_text(entry_data['title']),
                    'login': decrypted_login,
                    'password': decrypted_password
                })
            except Exception as e:
                logger.error(f"Decryption error for entry {entry_id}: {e}")
                continue

        return render_template("dashboard.html", username=username, entries=entries)

    except Exception as e:
        logger.error(f"Dashboard error for user {username}: {e}")
        flash("Error loading dashboard", "error")
        return redirect(url_for("logout"))

@app.route("/add_entry", methods=["GET", "POST"])
@login_required
def add_entry():
    username = session.get("username")
    
    if request.method == "POST":
        encryption_key_b64 = session.get("encryption_key")
        if not encryption_key_b64:
            flash("Session expired, please log in again", "error")
            return redirect(url_for("logout"))

        try:
            encryption_key = base64.b64decode(encryption_key_b64)
            
            title = request.form.get("title", "").strip()
            login_name = request.form.get("login", "")
            password = request.form.get("password", "")
            
            if not title or not password:
                flash("Title and password are required", "error")
                return redirect(url_for("add_entry"))

            user_passwords = load_user_passwords(username)
            entry_id = str(len(user_passwords) + 1)
            
            encrypted_login = encrypt_data(encryption_key, login_name) if login_name else None
            encrypted_password = encrypt_data(encryption_key, password)
            
            user_passwords[entry_id] = {
                'title': title,
                'login': encrypted_login,
                'password': encrypted_password,
                'created_at': datetime.now().isoformat()
            }
            
            save_user_passwords(username, user_passwords)
            flash("Password added successfully", "success")
            return redirect(url_for("dashboard"))
        
        except Exception as e:
            logger.error(f"Error adding entry for user {username}: {e}")
            flash("Error adding entry", "error")
            return redirect(url_for("add_entry"))

    return render_template("add.html")

@app.route("/delete_entry/<entry_id>", methods=["POST"])
@login_required
def delete_entry(entry_id):
    username = session.get("username")
    
    try:
        if not entry_id.isdigit():
            flash("Invalid entry ID", "error")
            return redirect(url_for("dashboard"))
        
        user_passwords = load_user_passwords(username)
        
        if entry_id in user_passwords:
            del user_passwords[entry_id]
            save_user_passwords(username, user_passwords)
            flash("Entry deleted successfully", "success")
        else:
            flash("Entry not found", "error")
    
    except Exception as e:
        logger.error(f"Error deleting entry for user {username}: {e}")
        flash("Error deleting entry", "error")
    
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info(f"User logged out: {username}")
    flash("Logged out", "info")
    return redirect(url_for("home"))

@app.route("/forgot")
def forgot():
    return render_template("forgot.html")

@app.route("/static/img/<path:filename>")
def serve_static(filename):
    if '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400
    return send_from_directory('static/img', filename)

# Запуск додатку
if __name__ == "__main__":
    upgrade_user_format()
    migrate_existing_users()
    print("🚀 Password Manager starting...")
    app.run(debug=True, host='127.0.0.1', port=5000)