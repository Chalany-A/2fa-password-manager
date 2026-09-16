# password_manager.py
"""
Správa uložených hesel v passwords databázi
"""

import sqlite3
from typing import Tuple, List, Dict, Optional
from database import DatabaseManager
from crypto import CryptoManager
from audit import AuditManager


class PasswordManager:
    """Správa uložených hesel v databázi"""
    
    def __init__(self):
        DatabaseManager.init_passwords_db()
        self.crypto = CryptoManager()
        self.audit = AuditManager()
    
    def save_password(self, user_id: int, service_name: str, password: str) -> Tuple[bool, str]:
        """
        Uložení hesla pro službu
        Heslo se šifruje pomocí Fernet + HMAC integrity tag
        Vrací (úspěch, zpráva)
        """
        try:
            # Načtení user_salt a password_hash pro odvození klíče
            users_conn = DatabaseManager.get_connection('users')
            users_cursor = users_conn.cursor()
            users_cursor.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
            user_row = users_cursor.fetchone()
            DatabaseManager.close_connection(users_conn)
            
            if not user_row:
                return False, "Uživatel nenalezen"
            
            user_salt, password_hash = user_row[0], user_row[1]
            user_key = self.crypto.derive_user_encryption_key(user_id, user_salt, password_hash)
            
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            # Šifrování hesla pomocí Fernet s user_key
            encrypted_password = self.crypto.encrypt_password(password, user_key)
            
            # Generování HMAC integrity tagu - závisí na password_hash
            integrity_tag = self.crypto.generate_integrity_tag(encrypted_password, user_id, user_salt, password_hash)
            
            cursor.execute('''
                INSERT INTO stored_passwords (user_id, service_name, password_hash, salt, integrity_tag)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, service_name, encrypted_password, 'fernet', integrity_tag))
            
            conn.commit()
            
            self.audit.log_action(
                user_id,
                "PASSWORD_SAVED",
                f"Heslo uloženo pro: {service_name}",
                "SUCCESS"
            )
            
            return True, "Heslo uloženo"
        except Exception as e:
            self.audit.log_action(
                user_id,
                "PASSWORD_SAVED",
                f"Chyba: {str(e)}",
                "FAILED"
            )
            return False, f"Chyba při ukládání: {str(e)}"
        finally:
            try:
                DatabaseManager.close_connection(conn)
            except:
                pass
    
    def verify_password(self, user_id: int, service_name: str, password: str) -> Tuple[bool, str]:
        """
        Ověření uloženého hesla
        Vrací (je_správné, zpráva)
        """
        try:
            # Načtení user_salt a password_hash pro odvození klíče
            users_conn = DatabaseManager.get_connection('users')
            users_cursor = users_conn.cursor()
            users_cursor.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
            user_row = users_cursor.fetchone()
            DatabaseManager.close_connection(users_conn)
            
            if not user_row:
                return False, "Uživatel nenalezen"
            
            user_salt, password_hash = user_row[0], user_row[1]
            user_key = self.crypto.derive_user_encryption_key(user_id, user_salt, password_hash)
            
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT password_hash, integrity_tag FROM stored_passwords 
                WHERE user_id = ? AND service_name = ?
            ''', (user_id, service_name))
            
            result = cursor.fetchone()
            
            if not result:
                DatabaseManager.close_connection(conn)
                return False, "Heslo pro tuto službu není uloženo"
            
            encrypted_password, integrity_tag = result[0], result[1]
            
            # Ověření integrity
            if not self.crypto.verify_integrity_tag(encrypted_password, user_id, user_salt, integrity_tag):
                DatabaseManager.close_connection(conn)
                self.audit.log_action(
                    user_id,
                    "PASSWORD_VERIFY_FAILED",
                    f"INTEGRITNÍ CHYBA pro: {service_name}",
                    "FAILED"
                )
                return False, "Integrita hesla porušena"
            
            # Dešifrování a ověření
            decrypted = self.crypto.decrypt_password(encrypted_password, user_key)
            
            if decrypted == password:
                self.audit.log_action(
                    user_id,
                    "PASSWORD_VERIFIED",
                    f"Heslo ověřeno pro: {service_name}",
                    "SUCCESS"
                )
                DatabaseManager.close_connection(conn)
                return True, "Heslo je správné"
            else:
                self.audit.log_action(
                    user_id,
                    "PASSWORD_VERIFY_FAILED",
                    f"Nesprávné heslo pro: {service_name}",
                    "FAILED"
                )
                DatabaseManager.close_connection(conn)
                return False, "Heslo je nesprávné"
        
        except Exception as e:
            return False, f"Chyba při ověřování hesla: {str(e)}"
    
    def get_password_list(self, user_id: int) -> List[Dict]:
        """
        Získání seznamu uložených hesel
        (bez samotných hesel z bezpečnostních důvodů)
        """
        try:
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, service_name, created_at, last_modified
                FROM stored_passwords WHERE user_id = ?
                ORDER BY created_at DESC
            ''', (user_id,))
            
            results = cursor.fetchall()
            DatabaseManager.close_connection(conn)
            
            passwords = []
            for row in results:
                passwords.append({
                    'id': row[0],
                    'service': row[1],
                    'created': row[2],
                    'modified': row[3]
                })
            
            return passwords
        
        except Exception as e:
            return []
    
    def get_password(self, user_id: int, service_name: str) -> Optional[str]:
        """
        Získání dešifrovaného hesla pro službu
        Vrací heslo v plaintextu nebo None
        """
        try:
            # Načtení user_salt a password_hash pro odvození klíče
            users_conn = DatabaseManager.get_connection('users')
            users_cursor = users_conn.cursor()
            users_cursor.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
            user_row = users_cursor.fetchone()
            DatabaseManager.close_connection(users_conn)
            
            if not user_row:
                return None
            
            user_salt, password_hash = user_row[0], user_row[1]
            user_key = self.crypto.derive_user_encryption_key(user_id, user_salt, password_hash)
            
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT password_hash, integrity_tag FROM stored_passwords 
                WHERE user_id = ? AND service_name = ?
            ''', (user_id, service_name))
            
            result = cursor.fetchone()
            
            if not result:
                DatabaseManager.close_connection(conn)
                return None
            
            encrypted_password, integrity_tag = result[0], result[1]
            
            # Ověření integrity dat - password_hash se musí shodovat
            if not self.crypto.verify_integrity_tag(encrypted_password, user_id, user_salt, password_hash, integrity_tag):
                DatabaseManager.close_connection(conn)
                self.audit.log_action(
                    user_id,
                    "INTEGRITY_FAILED",
                    f"Integrita dat selhala pro: {service_name}",
                    "FAILURE"
                )
                return None
            
            # Dešifrování hesla
            decrypted_password = self.crypto.decrypt_password(encrypted_password, user_key)
            DatabaseManager.close_connection(conn)
            return decrypted_password
        
        except Exception as e:
            return None
    
    def delete_password(self, user_id: int, service_name: str) -> Tuple[bool, str]:
        """Smazání uloženého hesla"""
        try:
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM stored_passwords 
                WHERE user_id = ? AND service_name = ?
            ''', (user_id, service_name))
            
            if cursor.rowcount == 0:
                DatabaseManager.close_connection(conn)
                return False, "Heslo nenalezeno"
            
            conn.commit()
            DatabaseManager.close_connection(conn)
            
            self.audit.log_action(
                user_id,
                "PASSWORD_DELETED",
                f"Heslo smazáno pro: {service_name}",
                "SUCCESS"
            )
            
            return True, "Heslo úspěšně smazáno"
        
        except Exception as e:
            return False, f"Chyba při mazání hesla: {str(e)}"
    
    def update_password(self, user_id: int, service_name: str, new_password: str) -> Tuple[bool, str]:
        """Aktualizace uloženého hesla (Fernet šifrování + HMAC)"""
        try:
            # Načtení user_salt a password_hash pro odvození klíče
            users_conn = DatabaseManager.get_connection('users')
            users_cursor = users_conn.cursor()
            users_cursor.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
            user_row = users_cursor.fetchone()
            DatabaseManager.close_connection(users_conn)
            
            if not user_row:
                return False, "Uživatel nenalezen"
            
            user_salt, password_hash = user_row[0], user_row[1]
            user_key = self.crypto.derive_user_encryption_key(user_id, user_salt, password_hash)
            
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            # Šifrování nového hesla
            encrypted_password = self.crypto.encrypt_password(new_password, user_key)
            
            # Generování nového HMAC integrity tagu - závisí na password_hash
            integrity_tag = self.crypto.generate_integrity_tag(encrypted_password, user_id, user_salt, password_hash)
            
            cursor.execute('''
                UPDATE stored_passwords 
                SET password_hash = ?, salt = ?, integrity_tag = ?, last_modified = CURRENT_TIMESTAMP
                WHERE user_id = ? AND service_name = ?
            ''', (encrypted_password, 'fernet', integrity_tag, user_id, service_name))
            
            if cursor.rowcount == 0:
                DatabaseManager.close_connection(conn)
                return False, "Heslo nenalezeno"
            
            conn.commit()
            DatabaseManager.close_connection(conn)
            
            self.audit.log_action(
                user_id,
                "PASSWORD_UPDATED",
                f"Heslo aktualizováno pro: {service_name}",
                "SUCCESS"
            )
            
            return True, "Heslo úspěšně aktualizováno"
        
        except Exception as e:
            return False, f"Chyba při aktualizaci hesla: {str(e)}"
    
    def count_passwords(self, user_id: int) -> int:
        """Počet uložených hesel"""
        try:
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM stored_passwords WHERE user_id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            DatabaseManager.close_connection(conn)
            
            return result[0] if result else 0
        except Exception:
            return 0