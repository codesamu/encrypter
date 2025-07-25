# Encrypter

![Python](https://img.shields.io/badge/Python-3.7%2B-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![cryptography](https://img.shields.io/badge/cryptography-%5E41.0.0-306998?style=for-the-badge&logo=pypi&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-4CAF50?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge&logo=checkmarx&logoColor=white)
![Security](https://img.shields.io/badge/Security-AES--GCM%20%7C%20PBKDF2-FF6F00?style=for-the-badge&logo=security&logoColor=white)

## Overview

**Encrypter** is a simple Python script to securely encrypt and decrypt all files in its directory (excluding Python scripts and already encrypted files) using AES-GCM encryption. It uses a password-based key derivation function (PBKDF2) for strong security.

## Features
- **Encrypts all files** in the script's directory (except `.py` and `.enc` files)
- **AES-GCM encryption** for confidentiality and integrity
- **Password-based key derivation** (PBKDF2 with SHA-256)
- **Easy to use**: just run the script and follow the prompts

## Requirements
- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies:
```bash
pip install cryptography
```

## Usage

1. Place `script.py` in the directory you want to encrypt/decrypt.
2. Run the script:
   ```bash
   python script.py
   ```
3. Choose `(E)ncrypt` or `(D)ecrypt` when prompted.
4. Enter your password.

- **Encryption:** All files (except `.py` and `.enc`) will be encrypted and replaced with `.enc` files. The original files are deleted after encryption (see `os.remove(file_path)` in the script).
- **Decryption:** All `.enc` files will be decrypted and restored to their original form. The `.enc` files are deleted after decryption (see `os.remove(file_path)` in the script).

## Security Notes
- Uses a random salt and IV for each file.
- The original files are deleted after encryption, and `.enc` files are deleted after decryption for security (see `os.remove(file_path)` in the code).
- If the wrong password is used during decryption, the script will warn you and skip the file.