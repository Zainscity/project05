# encryption_utils.py

import hashlib
import base64
from cryptography.fernet import Fernet

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_data(data, passkey):
    key = generate_key_from_passkey(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, passkey):
    try:
        key = generate_key_from_passkey(passkey)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return None

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
