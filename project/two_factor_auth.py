# two_factor_auth.py
"""
Správa dvoustupňové autentizace v twofa databázi
"""

import sqlite3
import json
import qrcode
from io import BytesIO
import base64
import time
from typing import Tuple, Optional, List
from database import DatabaseManager
from crypto import CryptoManager
from audit import AuditManager
from config import BACKUP_CODES_COUNT


class TwoFactorAuthManager:
    """Správa 2FA/TOTP autentizace v twofa databázi"""
    
    def __init__(self):
        DatabaseManager.init_twofa_db()
        self.crypto = CryptoManager()
        self.audit = AuditManager()
    
    def setup_2fa(self, user_id: int) -> Tuple[bool, str, Optional[str]]:
        """
        Nastavení 2FA - generování tajného klíče
        Vrací (úspěch, zpráva, secret_key)
        """
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            # Generování tajného klíče a záložních kódů
            secret_key = self.crypto.generate_secret_key()
            backup_codes = self.crypto.generate_backup_codes(BACKUP_CODES_COUNT)
            backup_codes_json = json.dumps(backup_codes)
            
            cursor.execute('''
                UPDATE two_factor_auth 
                SET secret_key = ?, backup_codes = ?
                WHERE user_id = ?
            ''', (secret_key, backup_codes_json, user_id))
            
            conn.commit()
            DatabaseManager.close_connection(conn)
            
            self.audit.log_action(user_id, "2FA_SETUP", "2FA inicializováno", "SUCCESS")
            
            return True, "2FA nastaveno", secret_key
        
        except Exception as e:
            return False, f"Chyba při nastavení 2FA: {str(e)}", None
    
    def enable_2fa(self, user_id: int, totp_code: str) -> Tuple[bool, str, Optional[List[str]]]:
        """
        Aktivace 2FA po ověření TOTP kódu s replay protection
        Vrací (úspěch, zpráva, seznam_záložních_kódů)
        """
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT secret_key, backup_codes, last_totp_code, last_totp_time 
                FROM two_factor_auth WHERE user_id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            if not result:
                return False, "2FA není inicializováno", None
            
            secret_key, backup_codes_json, last_totp_code, last_totp_time = result
            
            # Ověření TOTP kódu s replay protection
            is_valid, is_replay = self.crypto.verify_totp(
                secret_key, 
                totp_code,
                last_code=last_totp_code,
                last_time=last_totp_time
            )
            
            if is_replay:
                self.audit.log_action(
                    user_id, 
                    "2FA_ENABLE", 
                    "Replay útok detekován při aktivaci 2FA", 
                    "FAILED"
                )
                DatabaseManager.close_connection(conn)
                return False, "Opakované použití TOTP kódu (replay útok)", None
            
            if not is_valid:
                self.audit.log_action(user_id, "2FA_ENABLE", "Nesprávný TOTP kód", "FAILED")
                DatabaseManager.close_connection(conn)
                return False, "Nesprávný autentizační kód", None
            
            # Aktivace 2FA
            current_time = int(time.time())
            cursor.execute('''
                UPDATE two_factor_auth 
                SET enabled = 1, last_totp_code = ?, last_totp_time = ? 
                WHERE user_id = ?
            ''', (totp_code, current_time, user_id))
            
            conn.commit()
            
            backup_codes = json.loads(backup_codes_json)
            
            self.audit.log_action(user_id, "2FA_ENABLED", "2FA bylo aktivováno", "SUCCESS")
            
            DatabaseManager.close_connection(conn)
            
            return True, "2FA bylo úspěšně aktivováno", backup_codes
        
        except Exception as e:
            return False, f"Chyba při aktivaci 2FA: {str(e)}", None
    
    def disable_2fa(self, user_id: int) -> Tuple[bool, str]:
        """Deaktivace 2FA"""
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE two_factor_auth 
                SET enabled = 0, secret_key = '', backup_codes = ''
                WHERE user_id = ?
            ''', (user_id,))
            
            conn.commit()
            DatabaseManager.close_connection(conn)
            
            self.audit.log_action(user_id, "2FA_DISABLED", "2FA bylo deaktivováno", "SUCCESS")
            
            return True, "2FA bylo deaktivováno"
        
        except Exception as e:
            return False, f"Chyba při deaktivaci 2FA: {str(e)}"
    
    def verify_2fa(self, user_id: int, totp_code: str) -> bool:
        """Ověření 2FA kódu při přihlášení s replay protection"""
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT secret_key, enabled, last_totp_code, last_totp_time 
                FROM two_factor_auth WHERE user_id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            
            if not result or not result[1]:  # 2FA není povoleno
                DatabaseManager.close_connection(conn)
                return True  # Přihlášení bez 2FA je OK
            
            secret_key = result[0]
            last_totp_code = result[2]
            last_totp_time = result[3]
            
            # Ověření TOTP s replay protection
            is_valid, is_replay = self.crypto.verify_totp(
                secret_key, 
                totp_code,
                last_code=last_totp_code,
                last_time=last_totp_time
            )
            
            if is_replay:
                # Replay útok detekován
                self.audit.log_action(
                    user_id, 
                    "2FA_VERIFY", 
                    "Replay útok detekován - stejný TOTP kód znovu použit v krátké lhůtě", 
                    "FAILED"
                )
                DatabaseManager.close_connection(conn)
                return False
            
            if is_valid:
                # Uložení aktuálního kódu a času pro budoucí replay protection
                current_time = int(time.time())
                cursor.execute('''
                    UPDATE two_factor_auth 
                    SET last_totp_code = ?, last_totp_time = ? 
                    WHERE user_id = ?
                ''', (totp_code, current_time, user_id))
                conn.commit()
                self.audit.log_action(user_id, "2FA_VERIFY", "2FA ověřeno", "SUCCESS")
            else:
                self.audit.log_action(user_id, "2FA_VERIFY", "Nesprávný 2FA kód", "FAILED")
            
            DatabaseManager.close_connection(conn)
            return is_valid
        
        except Exception as e:
            self.audit.log_action(user_id, "2FA_VERIFY", f"Chyba při ověření 2FA: {str(e)}", "FAILED")
            return False
    
    def verify_backup_code(self, user_id: int, backup_code: str) -> bool:
        """Ověření a použití záložního kódu s replay protection"""
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            # Kontrola zda kód nebyl již použit (replay protection)
            conn_audit = DatabaseManager.get_connection('audit')
            cursor_audit = conn_audit.cursor()
            cursor_audit.execute('''
                SELECT id FROM backup_codes_log WHERE user_id = ? AND code = ?
            ''', (user_id, backup_code))
            
            if cursor_audit.fetchone():
                # Kód byl již jednou použit
                self.audit.log_action(
                    user_id, 
                    "BACKUP_CODE_REPLAY", 
                    f"Pokus o opakované použití záložního kódu (replay útok)", 
                    "FAILED"
                )
                DatabaseManager.close_connection(conn)
                DatabaseManager.close_connection(conn_audit)
                return False
            
            # Kontrola existence kódu v aktuálním seznamu
            cursor.execute('''
                SELECT backup_codes FROM two_factor_auth WHERE user_id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            if not result:
                DatabaseManager.close_connection(conn)
                DatabaseManager.close_connection(conn_audit)
                return False
            
            backup_codes = json.loads(result[0])
            
            if backup_code in backup_codes:
                # Kód je platný, zaznamenáme jeho použití
                backup_codes.remove(backup_code)
                cursor.execute('''
                    UPDATE two_factor_auth SET backup_codes = ? WHERE user_id = ?
                ''', (json.dumps(backup_codes), user_id))
                conn.commit()
                
                # Zaznamenáme do backup_codes_log (replay protection)
                try:
                    cursor_audit.execute('''
                        INSERT INTO backup_codes_log (user_id, code, used_at)
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                    ''', (user_id, backup_code))
                    conn_audit.commit()
                except sqlite3.IntegrityError:
                    # Duplikát - měl by být již odchycen výše
                    pass
                
                self.audit.log_action(user_id, "BACKUP_CODE_USED", "Záložní kód využit", "SUCCESS")
                
                DatabaseManager.close_connection(conn)
                DatabaseManager.close_connection(conn_audit)
                return True
            
            self.audit.log_action(user_id, "BACKUP_CODE_INVALID", "Neplatný záložní kód", "FAILED")
            DatabaseManager.close_connection(conn)
            DatabaseManager.close_connection(conn_audit)
            return False
        
        except Exception as e:
            self.audit.log_action(user_id, "BACKUP_CODE_ERROR", f"Chyba: {str(e)}", "FAILED")
            return False
    
    def get_2fa_status(self, user_id: int) -> dict:
        """Získání stavu 2FA"""
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT enabled, backup_codes FROM two_factor_auth WHERE user_id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            DatabaseManager.close_connection(conn)
            
            if result:
                backup_codes = json.loads(result[1]) if result[1] else []
                return {
                    'enabled': bool(result[0]),
                    'backup_codes_remaining': len(backup_codes)
                }
            return {'enabled': False, 'backup_codes_remaining': 0}
        
        except Exception:
            return {'enabled': False, 'backup_codes_remaining': 0}
    
    def generate_qr_code(self, user_id: int, username: str = "User") -> Optional[str]:
        """Generování QR kódu pro 2FA v base64 formátu"""
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT secret_key FROM two_factor_auth WHERE user_id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            DatabaseManager.close_connection(conn)
            
            if not result:
                return None
            
            secret_key = result[0]
            
            # Generování URI pro QR kód (TOTP standard)
            totp_uri = f"otpauth://totp/SecureAccountManager:{username}?secret={secret_key}&issuer=SecureAccountManager"
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return img_str
        
        except Exception as e:
            return None
    
    def get_remaining_backup_codes(self, user_id: int) -> int:
        """Získání počtu zbývajících záložních kódů"""
        try:
            conn = DatabaseManager.get_connection('twofa')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT backup_codes FROM two_factor_auth WHERE user_id = ?
            ''', (user_id,))
            
            result = cursor.fetchone()
            DatabaseManager.close_connection(conn)
            
            if result and result[0]:
                backup_codes = json.loads(result[0])
                return len(backup_codes)
            return 0
        except Exception:
            return 0