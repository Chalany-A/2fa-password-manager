# crypto.py
"""
Kryptografické funkce - hašování, šifrování, TOTP
"""

import hashlib
import hmac
import secrets
import base64
import time
import struct
from typing import Tuple
from cryptography.fernet import Fernet
from config import PBKDF2_ITERATIONS, SALT_LENGTH, MIN_PASSWORD_LENGTH


class CryptoManager:
    """Správa kryptografických operací"""
    
    @staticmethod
    def generate_salt(length: int = SALT_LENGTH) -> str:
        """Generování bezpečného saltu"""
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """
        Hašování hesla s PBKDF2
        Minimálně 100,000 iterací
        """
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            PBKDF2_ITERATIONS
        ).hex()
    
    @staticmethod
    def verify_password(password: str, salt: str, password_hash: str) -> bool:
        """Ověření hesla pomocí timing-safe porovnání"""
        return hmac.compare_digest(
            CryptoManager.hash_password(password, salt),
            password_hash
        )
    
    @staticmethod
    def generate_operation_nonce() -> str:
        """Generování jedinečného nonce pro deduplicaci operací (replay protection)"""
        return secrets.token_hex(16)
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """
        Ověření síly hesla
        Vrací (je_silné, zpráva)
        """
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Heslo musí mít alespoň {MIN_PASSWORD_LENGTH} znaků"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not has_upper:
            return False, "Heslo musí obsahovat velké písmeno"
        if not has_lower:
            return False, "Heslo musí obsahovat malé písmeno"
        if not has_digit:
            return False, "Heslo musí obsahovat číslici"
        if not has_special:
            return False, "Heslo musí obsahovat speciální znak (!@#$%^&* atd.)"
        
        return True, "Heslo je dostatečně silné"
    
    @staticmethod
    def _base32_decode(b32_string: str) -> bytes:
        """Dekódování Base32 řetězce na bajty"""
        # Doplnění padding znaků pokud chybí
        b32_string = b32_string.upper().replace(' ', '')
        padding = (8 - len(b32_string) % 8) % 8
        b32_string += '=' * padding
        try:
            return base64.b32decode(b32_string)
        except Exception:
            return b''
    
    @staticmethod
    def generate_secret_key() -> str:
        """Generování tajného klíče pro 2FA (Base32)"""
        # Generování 20 náhodných bajtů a kódování do Base32
        random_bytes = secrets.token_bytes(20)
        return base64.b32encode(random_bytes).decode('utf-8')
    
    @staticmethod
    def encrypt_password(password: str, user_key: str) -> str:
        """Šifrování hesla pro uložení v DB - vyžaduje user_key"""
        try:
            cipher = Fernet(user_key.encode())
            encrypted = cipher.encrypt(password.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception:
            return ""
    
    @staticmethod
    def decrypt_password(encrypted_password: str, user_key: str) -> str:
        """Dešifrování hesla z DB - vyžaduje user_key"""
        try:
            cipher = Fernet(user_key.encode())
            decrypted = cipher.decrypt(encrypted_password.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception:
            return ""
    
    @staticmethod
    def derive_user_encryption_key(user_id: int, password_salt: str, password_hash: str) -> str:
        """Odvození uživatelem specifického encryption klíče z hesla, salt a user_id"""
        try:
            # Klíč se odvozuje z user_id + salt + password_hash (závislý na heslu!)
            kdf_input = f"{user_id}:{password_salt}:{password_hash}".encode()
            # PBKDF2 derivace
            derived = hashlib.pbkdf2_hmac(
                'sha256',
                kdf_input,
                b'user_audit_encryption_salt',
                50000
            )
            # Konverze na Fernet-compatible key (base64 encoded 32 bajtů)
            key = base64.urlsafe_b64encode(derived[:32])
            return key.decode('utf-8')
        except Exception:
            return None
    
    @staticmethod
    def encrypt_secret_key(secret: str, user_key: str) -> str:
        """Šifrování TOTP secret pro uložení v DB - vyžaduje user_key"""
        try:
            cipher = Fernet(user_key.encode())
            encrypted = cipher.encrypt(secret.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception:
            return ""
    
    @staticmethod
    def decrypt_secret_key(encrypted_secret: str, user_key: str) -> str:
        """Dešifrování TOTP secret z DB - vyžaduje user_key"""
        try:
            cipher = Fernet(user_key.encode())
            decrypted = cipher.decrypt(encrypted_secret.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception:
            return ""
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> list:
        """Generování záložních kódů"""
        return [secrets.token_hex(4).upper() for _ in range(count)]
    
    @staticmethod
    def _generate_hotp(secret: bytes, counter: int, digits: int = 6) -> str:
        """Generování HOTP kódu (RFC 4226)"""
        # Vytvoření zprávy z čítače
        message = struct.pack('>Q', counter)
        
        # Výpočet HMAC-SHA1
        hmac_digest = hmac.new(secret, message, hashlib.sha1).digest()
        
        # Dynamické zkrácení (Dynamic Truncation)
        offset = hmac_digest[-1] & 0x0f
        code = struct.unpack('>I', hmac_digest[offset:offset+4])[0]
        code = code & 0x7fffffff
        code = code % (10 ** digits)
        
        return str(code).zfill(digits)
    
    @staticmethod
    def verify_totp(secret_key: str, totp_code: str, window: int = 1, last_code: str = None, last_time: int = None) -> Tuple[bool, bool]:
        """Ověření TOTP kódu (RFC 6238) s replay protection
        window: počet 30-sekundových intervalů, které se mají zkontrolovat
        last_code: poslední použitý kód (pro replay protection)
        last_time: čas poslední použití (pro replay protection)
        Vrací (je_platný, je_replay_útok)
        """
        try:
            secret = CryptoManager._base32_decode(secret_key)
            if not secret:
                return False, False
            
            # Aktuální časový interval 
            time_counter = int(time.time()) // 30
            current_time = int(time.time())
            
            # Kontrola aktuálního a sousedních intervalů (window)
            for i in range(-window, window + 1):
                test_counter = time_counter + i
                test_code = CryptoManager._generate_hotp(secret, test_counter)
                if hmac.compare_digest(test_code, totp_code.strip()):
                    # Kód je platný, ale kontrolujeme replay protection
                    if last_code and last_time:
                        # Pokud je kód stejný jako poslední a není starší než 31 sekund (window)
                        if hmac.compare_digest(test_code, last_code) and (current_time - last_time) < 31:
                            # Replay útok detekován!
                            return True, True
                    return True, False
            
            return False, False
        except Exception:
            return False, False
    
    @staticmethod
    def get_totp_code(secret_key: str) -> str:
        """Získání aktuálního TOTP kódu"""
        try:
            secret = CryptoManager._base32_decode(secret_key)
            if not secret:
                return ""
            
            time_counter = int(time.time()) // 30
            return CryptoManager._generate_hotp(secret, time_counter)
        except Exception:
            return ""
    
    # ============= ŠIFROVÁNÍ AUDIT LOGU =============
    
    @staticmethod
    def encrypt_audit_data(data: str, user_key: str) -> str:
        """
        Šifrování audit dat pro uložení
        Pomocí Fernet (AES-128-CBC)
        VYŽADUJE user_key - nikdy se nepoužívá master klíč přímo
        """
        try:
            cipher = Fernet(user_key.encode())
            encrypted = cipher.encrypt(data.encode('utf-8'))
            return encrypted.decode('utf-8')
        except Exception as e:
            print(f"Chyba při šifrování: {str(e)}")
            return ""
    
    @staticmethod
    def decrypt_audit_data(encrypted_data: str, user_key: str) -> str:
        """
        Dešifrování audit dat
        VYŽADUJE user_key - nikdy se nepoužívá master klíč přímo
        """
        try:
            cipher = Fernet(user_key.encode())
            decrypted = cipher.decrypt(encrypted_data.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Chyba při dešifrování: {str(e)}")
            return ""
    
    @staticmethod
    def generate_integrity_tag(data: str, user_id: int, user_salt: str, password_hash: str) -> str:
        """
        Generování HMAC integrity tagu pro kontrolu neporušenosti dat
        HMAC klíč je odvozený z user_key (user_id + user_salt + password_hash)
        Klíč se měnit, pokud uživatel změní heslo
        """
        # Odvození klíče stejným způsobem jako user_key - z user_id + salt + password_hash
        kdf_input = f"{user_id}:{user_salt}:{password_hash}".encode()
        hmac_key = hashlib.pbkdf2_hmac(
            'sha256',
            kdf_input,
            b'integrity_salt',
            50000  # Stejně jako u derivace encryption klíče
        )
        tag = hmac.new(hmac_key, data.encode(), hashlib.sha256).digest()
        return base64.b64encode(tag).decode()
    
    @staticmethod
    def verify_integrity_tag(data: str, user_id: int, user_salt: str, password_hash: str, tag: str) -> bool:
        """
        Ověření integrity HMAC tagu
        Vrací True pokud je data intaktní
        password_hash se musí shodovat (pokud se heslo změní, budou všechny HMAC tagy neplatné)
        """
        expected_tag = CryptoManager.generate_integrity_tag(data, user_id, user_salt, password_hash)
        return hmac.compare_digest(expected_tag, tag)
