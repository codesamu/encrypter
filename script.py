import os
import shutil
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import sys

backend = default_backend()
iterations = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password.encode())

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

def encrypt_folder(root_dir: str, password: str):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for file in filenames:
            full_path = os.path.join(dirpath, file)
            if not full_path.endswith(".enc") and not full_path.endswith(".py"):
                encrypt_file(full_path, password)

def decrypt_folder(root_dir: str, password: str):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for file in filenames:
            if file.endswith(".enc"):
                full_path = os.path.join(dirpath, file)
                decrypt_file(full_path, password)

if __name__ == "__main__":
    mode = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().lower()
    password = input("Enter password: ").strip()
    base_dir = os.path.dirname(os.path.abspath(__file__))  # folder script is in

    if mode == "e":
        encrypt_folder(base_dir, password)
    elif mode == "d":
        decrypt_folder(base_dir, password)
    else:
        print("Invalid option.")
