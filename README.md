# Encrypter

![Python](https://img.shields.io/badge/Python-3.7%2B-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![cryptography](https://img.shields.io/badge/cryptography-%5E41.0.0-306998?style=for-the-badge&logo=pypi&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-4CAF50?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge&logo=checkmarx&logoColor=white)
![Security](https://img.shields.io/badge/Security-AES--GCM%20%7C%20PBKDF2-FF6F00?style=for-the-badge&logo=security&logoColor=white)

## Overview

**Encrypter** is a simple Python tool to securely encrypt and decrypt all files in its directory (excluding Python scripts and already encrypted files) using AES-GCM encryption. It uses a password-based key derivation function (PBKDF2) for strong security.

## How it Works

- **encrypt.py**: Encrypts all files in the directory. It generates a strong random password, uses it for encryption, and displays it **once** in the terminal. The password is never stored in plaintext. Instead, a hash of the password is stored in an encrypted file (`password.hash.enc`) using a key (`key.bin`).
- **decrypt.py**: Prompts you for the password. It decrypts the stored hash and verifies your input before decrypting the files.

> **WARNING:**
> - The password is shown only once when you run `encrypt.py`. **You must save it immediately and keep it safe.**
> - If you lose the password, you will not be able to decrypt your files. There is no recovery method.

## Features
- **Encrypts all files** in the script's directory (except `.py` and `.enc` files)
- **AES-GCM encryption** for confidentiality and integrity
- **Password-based key derivation** (PBKDF2 with SHA-256)
- **No password prompt during encryption**; password is generated and shown once
- **Password hash is stored encrypted, not in plaintext**

## Requirements
- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies:
```bash
pip install cryptography
```

## Usage

### Encrypting Files
1. Place `encrypt.py` in the directory you want to encrypt.
2. Run the script:
   ```bash
   python encrypt.py
   ```
3. **Copy and save the password shown in the terminal.** You will need it to decrypt your files.

### Decrypting Files
1. Place `decrypt.py` in the same directory (with `password.hash.enc` and `key.bin`).
2. Run the script:
   ```bash
   python decrypt.py
   ```
3. Enter the password you saved when prompted.

- **Encryption:** All files (except `.py` and `.enc`) will be encrypted and replaced with `.enc` files. The original files are deleted after encryption.
- **Decryption:** All `.enc` files will be decrypted and restored to their original form. The `.enc` files are deleted after decryption.

## Security Notes
- Uses a random salt and IV for each file.
- The original files are deleted after encryption, and `.enc` files are deleted after decryption for security.
- If the wrong password is used during decryption, the script will warn you and skip the file.
- The password is never stored in plaintext—only a hash (encrypted) is kept, which is not reversible.

## FAQ

**Q: What if I lose the password?**
> You will not be able to decrypt your files. There is no recovery method.

**Q: Can I use the same password for multiple encryptions?**
> Each run generates a new random password. Save each password separately for each encryption session.