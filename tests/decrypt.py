import os
import sys
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

backend = default_backend()
iterations = 100_000
HASH_FILE = "password.hash.enc"
KEY_FILE = "key.bin"

# --- Password and Key Utilities ---
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

def load_key(key_file: str = KEY_FILE) -> bytes:
    with open(key_file, 'rb') as f:
        return f.read()

def verify_password(input_password: str, hash_file: str = HASH_FILE, key_file: str = KEY_FILE) -> bool:
    key = load_key(key_file)
    with open(hash_file, 'rb') as f:
        content = f.read()
    nonce = content[:12]
    enc_data = content[12:]
    aesgcm = AESGCM(key)
    try:
        data = aesgcm.decrypt(nonce, enc_data, None)
    except Exception:
        print("❌ Could not decrypt password hash. Wrong key or corrupted file.")
        return False
    salt = data[:16]
    stored_hash = data[16:]
    input_hash = hash_password(input_password, salt)
    return input_hash == stored_hash

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        encrypted_content = f.read()
    salt = encrypted_content[:16]
    iv = encrypted_content[16:28]
    tag = encrypted_content[28:44]
    ciphertext = encrypted_content[44:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        print(f"❌ Invalid password or corrupted file: {file_path}")
        return
    output_file = file_path[:-4]  # Remove .enc
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    os.remove(file_path)
    print(f"[+] Decrypted: {file_path}")

def decrypt_folder(root_dir: str, password: str):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for file in filenames:
            if file.endswith(".enc") and file not in [HASH_FILE]:
                full_path = os.path.join(dirpath, file)
                decrypt_file(full_path, password)

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    hash_path = os.path.join(base_dir, HASH_FILE)
    key_path = os.path.join(base_dir, KEY_FILE)
    if not os.path.exists(hash_path) or not os.path.exists(key_path):
        print(f"Password hash or key file not found. Cannot decrypt.")
        sys.exit(1)
    password = input("Enter password: ").strip()
    if not verify_password(password, hash_path, key_path):
        print("❌ Password does not match stored hash. Aborting decryption.")
        sys.exit(1)
    decrypt_folder(base_dir, password) 