# Web-Based Secure Password Manager

## Overview
This project is a web-based secure password manager developed as part of the ICS0020 course.  
It focuses on secure credential storage, user authentication, and protection against common web vulnerabilities such as SQL Injection, XSS, and CSRF.  

The password manager allows users to securely store, retrieve, and manage passwords with AES encryption, optional Multi-Factor Authentication (MFA), and secure session management.

---

## Features

- **Secure Credential Storage:**  
  User passwords are encrypted with AES. Encryption keys are derived from the master password using PBKDF2 with a unique salt per user.

- **User Authentication & MFA:**  
  Master password authentication with optional TOTP-based Multi-Factor Authentication (MFA).  

- **Session Security & Secure Cookies:**  
  Sessions are secured using `SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SAMESITE`.  
  CSRF protection is enabled for all forms using Flask-WTF.  

- **Protection Against Attacks:**  
  - SQL Injection: No SQL database used, secure storage with encrypted JSON.  
  - XSS: User inputs are escaped in templates.  
  - CSRF: All POST forms include CSRF tokens.  
  - Brute-force login protection: Failed login attempts are limited, temporary blocking implemented.  

- **Access Control:**  
  Each user can only access their own passwords and data.  

- **Error Handling & Logging:**  
  Generic error messages for users, detailed logging for developers.  

---

## Project Structure

MPPA/
├── .venv/                    # Python virtual environment
├── __pycache__/              # Python cache files
├── Include/                  # Include files (typically for virtual environment)
├── Lib/                      # Python libraries (for virtual environment)
├── Scripts/                  # Scripts (for virtual environment)
├── app/                      # Main application directory
├── logs/                     # Directory for log files
├── static/
│   └── img/                  # Static images
├── templates/                # HTML templates
│   ├── add.html
│   ├── dashboard.html
│   ├── forgot.html
│   ├── index.html
│   ├── login.html
│   ├── model.html
│   ├── register.html
│   ├── setup_infa.html
│   └── welcome.html
├── app.log                   # Application log file
├── auth.py                   # Authentication module
├── encryption.py             # Encryption module
├── main.py                   # Main application file
├── passwords.json            # Passwords file (encrypted)
├── storage.py                # Storage handling module
├── upgrade_users.py          # User upgrade script
├── users.json                # User data file
└── pyvenv.cfg               # Virtual environment configuration

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/sonyyyk/mypasswdmanadger.git
cd project


Usage

Register: Create a new user with a master password (at least 16 characters, must include uppercase, lowercase, and a number).
MFA Setup: Scan the QR code with a TOTP authenticator app.
Login: Enter username, password, and MFA code.
Dashboard: Add, view, and delete password entries securely.



Security Details

Encryption: AES symmetric encryption for stored passwords.
Key Derivation: PBKDF2 with per-user salt.

MFA: TOTP (Time-based One-Time Password).
CSRF Protection: All POST forms include csrf_token.

Session Security: SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE=Lax, session expiration handled.
Brute-force protection: Maximum 3 failed login attempts, blocked for 60 seconds.

XSS & Input Validation: All user input escaped in templates, username validated with regex.


