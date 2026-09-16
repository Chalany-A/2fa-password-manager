# config.py
"""
Konfigurační soubor pro správce hesel
Podpora více databází se šifrováním
"""

import os
from cryptography.fernet import Fernet

# Databáze - více souborů
DATABASES = {
    'users': os.getenv('DB_USERS', 'db/users.db'),
    'passwords': os.getenv('DB_PASSWORDS', 'db/passwords.db'),
    'twofa': os.getenv('DB_TWOFA', 'db/twofa.db'),
    'audit': os.getenv('DB_AUDIT', 'db/audit.db'),
}

# Vytvoření adresáře db pokud neexistuje
try:
    os.makedirs('db', exist_ok=True)
except OSError as e:
    print(f"Varování: Nelze vytvořit adresář 'db': {e}")

# Bezpečnost
MIN_PASSWORD_LENGTH = 12
PBKDF2_ITERATIONS = 100000
SALT_LENGTH = 32

# 2FA
BACKUP_CODES_COUNT = 10
TOTP_WINDOW = 1

# Audit
AUDIT_LOG_LIMIT = 50

# Audit encryption klíč se odvozuje z hesla uživatele v runtime
# Není nikdy uložen - existuje jen v paměti během session