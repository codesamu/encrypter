import os
import sys
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

backend = default_backend()
iterations = 100_000
HASH_FILE = "password.hash.enc"
KEY_FILE = "key.bin"

# --- Password and Key Utilities ---
def generate_password(length=32):
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8')[:length]

def hash_password(password: str, salt: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    digest.update(salt + password.encode())
    return digest.finalize()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password.encode())

# --- Store password hash in encrypted form ---
def store_encrypted_hash(password: str, key: bytes, hash_file: str = HASH_FILE):
    salt = os.urandom(16)
    pw_hash = hash_password(password, salt)
    data = salt + pw_hash
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    enc_data = aesgcm.encrypt(nonce, data, None)
    with open(hash_file, 'wb') as f:
        f.write(nonce + enc_data)

def generate_key(key_file: str = KEY_FILE) -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    with open(key_file, 'wb') as f:
        f.write(key)
    return key

def load_key(key_file: str = KEY_FILE) -> bytes:
    with open(key_file, 'rb') as f:
        return f.read()

# --- Encryption Logic ---
def encrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    encrypted_file_content = salt + iv + encryptor.tag + encrypted_data
    with open(file_path + ".enc", 'wb') as f:
        f.write(encrypted_file_content)
    os.remove(file_path)
    print(f"[+] Encrypted: {file_path}")

def encrypt_folder(root_dir: str, password: str):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for file in filenames:
            full_path = os.path.join(dirpath, file)
            if not full_path.endswith(".enc") and not full_path.endswith(".py") and file not in [HASH_FILE, KEY_FILE]:
                encrypt_file(full_path, password)

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # Generate random password
    password = generate_password()
    # Generate key for encrypting the hash
    key = generate_key(os.path.join(base_dir, KEY_FILE))
    # Store encrypted hash
    store_encrypted_hash(password, key, os.path.join(base_dir, HASH_FILE))
    # Encrypt files
    encrypt_folder(base_dir, password)
    print(f"[+] Password hash stored in '{HASH_FILE}' (encrypted). Key stored in '{KEY_FILE}'.")
    print("[!] Save the password below in a safe place. You will need it to decrypt your files:")
    print(password) 