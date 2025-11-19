import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(master_password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode('utf-8'))
    return key, salt

def encrypt_data(key: bytes, data: str) -> dict:
    if not data:
        return None
        
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
    
    return {
        'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8')
    }

def decrypt_data(key: bytes, encrypted_dict: dict) -> str:
    if not encrypted_dict:
        return ""
        
    ciphertext = base64.b64decode(encrypted_dict['ciphertext'])
    nonce = base64.b64decode(encrypted_dict['nonce'])
    
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_data.decode('utf-8')