# 2fa-password-manager

A two-factor authentication password manager developed as a university project.

## Features

- AES-128-CBC and Fernet encryption
- SHA256 and HMAC-SHA256 integrity verification
- GUI (PySide6) for managing passwords and configurations
- Two-factor authentication (2FA) via TOTP generated as QR code
- Per-user encryption and integrity settings
- Secure audit logging

## Instalation of required libraries

```bash
pip3 install PySide6 cryptography qrcode pillow
```

## Running the Application

```bash
python3 main.py
```

## Security Notice

This program is intended for educational use only and should not be used for storing of sensitive data.
For real-world 2FA solutions, internal implementation details (like encryption logic or code structure) should never be publicly exposed, to reduce the attack surface.

## Data Security Overview

- All user data is encrypted using Fernet algorithm
- Encryption keys are derived using PBKDF2-HMAC-SHA256 with a per-user random salt
- Each password vault includes integrity verification
- All data is stored locally in JSON files (no cloud usage)
