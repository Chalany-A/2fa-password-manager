# user.py
"""
Správa uživatelských účtů v uživatelské databázi
"""

import sqlite3
from typing import Tuple, Optional
from database import DatabaseManager
from crypto import CryptoManager
from audit import AuditManager


class UserManager:
    """Správa uživatelských účtů"""
    
    def __init__(self):
        DatabaseManager.init_users_db()
        DatabaseManager.init_twofa_db()
        self.crypto = CryptoManager()
        self.audit = AuditManager()
    
    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Registrace nového uživatele
        Vrací (úspěch, zpráva)
        """
        try:
            # Validace síly hesla
            is_strong, msg = self.crypto.validate_password_strength(password)
            if not is_strong:
                self.audit.log_action(
                    None,
                    "REGISTER",
                    f"Slabé heslo pro: {username}",
                    "FAILED"
                )
                return False, msg
            
            conn = DatabaseManager.get_connection('users')
            cursor = conn.cursor()
            
            # Generování saltu a hašování hesla
            salt = self.crypto.generate_salt()
            password_hash = self.crypto.hash_password(password, salt)
            
            # Vložení uživatele
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            ''', (username, password_hash, salt))
            
            user_id = cursor.lastrowid
            
            conn.commit()
            DatabaseManager.close_connection(conn)
            
            # Vytvoření 2FA záznamu v twofa DB
            conn_twofa = DatabaseManager.get_connection('twofa')
            cursor_twofa = conn_twofa.cursor()
            
            cursor_twofa.execute('''
                INSERT INTO two_factor_auth (user_id, secret_key, backup_codes, enabled)
                VALUES (?, ?, ?, 0)
            ''', (user_id, '', ''))
            
            conn_twofa.commit()
            DatabaseManager.close_connection(conn_twofa)
            
            self.audit.log_action(user_id, "REGISTER", "Uživatel registrován", "SUCCESS")
            
            return True, "Uživatel úspěšně registrován"
        
        except sqlite3.IntegrityError:
            self.audit.log_action(
                None,
                "REGISTER",
                f"Pokus o registraci existujícího uživatele: {username}",
                "FAILED"
            )
            return False, "Uživatelské jméno již existuje"
        except Exception as e:
            return False, f"Chyba při registraci: {str(e)}"
    
    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[int]]:
        """
        Přihlášení uživatele
        Vrací (úspěch, zpráva, user_id)
        """
        try:
            conn = DatabaseManager.get_connection('users')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, password_hash, salt FROM users WHERE username = ?
            ''', (username,))
            
            result = cursor.fetchone()
            
            if not result:
                self.audit.log_action(
                    None,
                    "LOGIN",
                    f"Pokus o přihlášení neexistujícího uživatele: {username}",
                    "FAILED"
                )
                return False, "Neplatné uživatelské jméno nebo heslo", None
            
            user_id, password_hash, salt = result
            
            # Ověření hesla
            if not self.crypto.verify_password(password, salt, password_hash):
                self.audit.log_action(user_id, "LOGIN", f"Nesprávné heslo pro: {username}", "FAILED")
                return False, "Neplatné uživatelské jméno nebo heslo", None
            
            # Aktualizace času posledního přihlášení
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            
            conn.commit()
            
            self.audit.log_action(user_id, "LOGIN", "Úspěšné přihlášení", "SUCCESS")
            
            return True, "Přihlášení úspěšné", user_id
        
        except Exception as e:
            self.audit.log_action(None, "LOGIN", f"Chyba při přihlášení: {str(e)}", "FAILED")
            return False, f"Chyba při přihlášení: {str(e)}", None
        finally:
            try:
                DatabaseManager.close_connection(conn)
            except:
                pass
    
    def get_user_info(self, user_id: int) -> Optional[dict]:
        """Získání informací o uživateli"""
        try:
            conn = DatabaseManager.get_connection('users')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, created_at, last_login FROM users WHERE id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            DatabaseManager.close_connection(conn)
            
            if result:
                return {
                    'id': result[0],
                    'username': result[1],
                    'created_at': result[2],
                    'last_login': result[3]
                }
            return None
        except Exception:
            return None
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Změna hesla uživatele"""
        try:
            conn = DatabaseManager.get_connection('users')
            cursor = conn.cursor()
            
            # Ověření starého hesla
            cursor.execute('''
                SELECT password_hash, salt FROM users WHERE id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            if not result:
                return False, "Uživatel nenalezen"
            
            password_hash, salt = result
            
            if not self.crypto.verify_password(old_password, salt, password_hash):
                self.audit.log_action(user_id, "PASSWORD_CHANGE", "Nesprávné staré heslo", "FAILED")
                return False, "Staré heslo je nesprávné"
            
            # Validace nového hesla
            is_strong, msg = self.crypto.validate_password_strength(new_password)
            if not is_strong:
                return False, msg
            
            # Změna hesla
            new_salt = self.crypto.generate_salt()
            new_password_hash = self.crypto.hash_password(new_password, new_salt)
            
            cursor.execute('''
                UPDATE users SET password_hash = ?, salt = ? WHERE id = ?
            ''', (new_password_hash, new_salt, user_id))
            
            conn.commit()
            
            self.audit.log_action(user_id, "PASSWORD_CHANGE", "Heslo úspěšně změněno", "SUCCESS")
            
            return True, "Heslo úspěšně změněno"
        
        except Exception as e:
            self.audit.log_action(user_id, "PASSWORD_CHANGE", f"Chyba: {str(e)}", "FAILED")
            return False, f"Chyba při změně hesla: {str(e)}"
        finally:
            try:
                DatabaseManager.close_connection(conn)
            except:
                pass