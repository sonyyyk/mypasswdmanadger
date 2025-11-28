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
templates/                # HTML templates

- app.log                   # Application log file
- auth.py                   # Authentication module
- encryption.py             # Encryption module
- main.py                   # Main application file
- passwords.json            # Passwords file (encrypted)
- storage.py                # Storage handling module
- upgrade_users.py          # User upgrade script
- users.json                # User data file


# Technologies Used

## Backend
- **Flask** (routing, sessions, templates)
- **Python 3**

## Security & Cryptography
- **cryptography** — AES-256-GCM encryption
- **argon2-cffi** — Argon2id secure hashing
- **pyotp** — TOTP MFA support
- **qrcode** — QR code generation
- **PBKDF2** password-based key derivation

## Data Storage
- Encrypted JSON file using AES-256-GCM
- Authenticated encryption (nonce + tag)

## Frontend
- HTML templates
- CSS styling (minimal UI)

# Security Architecture

## 1. Password Hashing (Argon2id)
User passwords are hashed with Argon2id, offering strong resistance to brute-force and GPU attacks.

## 2. Master Key Derivation
On login, the system derives:
`Master Key = PBKDF2(user_password + user_salt)`

Master keys are never stored, only generated during login.

## 3. Full AES-GCM Vault Encryption
All user data inside passwords.json is fully encrypted:
- AES-256-GCM
- Unique nonce
- Authentication tag
- No plaintext ever stored on disk

## 4. Multi-Factor Authentication (TOTP)
Supports popular authenticator apps:
- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password OTP

A QR code is generated automatically during registration.

## 5. Login Security
- Brute-force protection
- Lockout after repeated failed attempts
- Secure session cookies
- CSRF protection enabled
- No sensitive data stored in session