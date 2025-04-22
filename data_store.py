# data_store.py

from encryption_utils import encrypt_data, decrypt_data, hash_passkey

# In-memory dictionary to simulate storage
stored_data = {}

def store_data(user_key, text_data, passkey):
    if user_key in stored_data:
        return False, "User Key already exists."
    encrypted = encrypt_data(text_data, passkey)
    stored_data[user_key] = {
        "encrypted_text": encrypted,
        "passkey": hash_passkey(passkey)
    }
    return True, "Data encrypted and stored successfully!"

def retrieve_data(user_key, passkey):
    entry = stored_data.get(user_key)
    if not entry:
        return False, "No data found for this User Key."
    if hash_passkey(passkey) == entry["passkey"]:
        decrypted = decrypt_data(entry["encrypted_text"], passkey)
        if decrypted:
            return True, decrypted
        return False, "Decryption failed."
    return False, "Incorrect passkey."
