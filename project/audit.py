# audit.py
"""
Správa šifrovaného audit logu v samostatné databázi
"""

import sqlite3
import json
from typing import Optional, List, Dict
from datetime import datetime
from database import DatabaseManager
from crypto import CryptoManager


class AuditManager:
    """Správa šifrovaného audit logu"""
    
    def __init__(self):
        DatabaseManager.init_audit_db()
        self.crypto = CryptoManager()
    
    def log_action(
        self,
        user_id: Optional[int],
        action: str,
        details: str,
        status: str,
        ip_address: Optional[str] = None,
        operation_nonce: Optional[str] = None
    ) -> bool:
        """
        Záznam akce do šifrovaného audit logu s optional nonce pro replay protection
        Data jsou šifrována pomocí user-specific klíče (pokud user_id existuje)
        operation_nonce: jedinečný identifikátor operace pro deduplicaci (replay protection)
        """
        try:
            # Pokud je user_id, odvozíme user_key
            user_key = None
            if user_id:
                try:
                    users_conn = DatabaseManager.get_connection('users')
                    users_cursor = users_conn.cursor()
                    users_cursor.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
                    user_row = users_cursor.fetchone()
                    DatabaseManager.close_connection(users_conn)
                    
                    if user_row:
                        user_salt, password_hash = user_row[0], user_row[1]
                        user_key = self.crypto.derive_user_encryption_key(user_id, user_salt, password_hash)
                except Exception:
                    pass
            
            # Generování nonce pokud nebyl poskytnut
            if not operation_nonce:
                operation_nonce = self.crypto.generate_operation_nonce()
            
            # Pokud nemáme user_key, audit se zapíše bez šifrování (jen pro systémové akce)
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            # Šifrování dat pokud je dostupný user_key
            if user_key:
                encrypted_action = self.crypto.encrypt_audit_data(action, user_key)
                encrypted_details = self.crypto.encrypt_audit_data(details, user_key)
                encrypted_ip = self.crypto.encrypt_audit_data(ip_address, user_key) if ip_address else None
            else:
                # Pro systémové logy bez uživatele - uložit v plaintext
                encrypted_action = action
                encrypted_details = details
                encrypted_ip = ip_address
            
            # Lokální čas (nikoliv UTC)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                INSERT INTO audit_log (user_id, action, details, status, ip_address, encrypted, timestamp, operation_nonce)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, encrypted_action, encrypted_details, status, encrypted_ip, 1 if user_key else 0, timestamp, operation_nonce))
            
            conn.commit()
            DatabaseManager.close_connection(conn)
            return True
        except sqlite3.IntegrityError as e:
            # Duplikátní nonce - replay útok detekován
            print(f"Replay útok detekován - duplikátní operační nonce: {str(e)}")
            return False
        except Exception as e:
            print(f"Chyba při zápisu do audit logu: {str(e)}")
            return False
    
    def get_user_audit_log(
        self,
        user_id: int,
        limit: int = 50,
        action_filter: Optional[str] = None,
        decrypt: bool = True
    ) -> List[Dict]:
        """
        Získání audit logu uživatele
        Automaticky dešifruje data s user-specific klíčem
        """
        try:
            # Načtení salt a password_hash uživatele pro odvození klíče
            user_key = None
            try:
                users_conn = DatabaseManager.get_connection('users')
                users_cursor = users_conn.cursor()
                users_cursor.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
                user_row = users_cursor.fetchone()
                DatabaseManager.close_connection(users_conn)
                
                if user_row:
                    user_salt, password_hash = user_row[0], user_row[1]
                    user_key = self.crypto.derive_user_encryption_key(user_id, user_salt, password_hash)
            except Exception as e:
                print(f"Chyba při načtení user salt: {str(e)}")
                return []
            
            if not user_key:
                return []
            
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, action, details, status, timestamp
                FROM audit_log WHERE user_id = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (user_id, limit))
            
            results = cursor.fetchall()
            DatabaseManager.close_connection(conn)
            
            logs = []
            for row in results:
                log_id, encrypted_action, encrypted_details, status, timestamp = row
                
                # Dešifrování dat s user-specific klíčem
                if decrypt:
                    action = self.crypto.decrypt_audit_data(encrypted_action, user_key)
                    details = self.crypto.decrypt_audit_data(encrypted_details, user_key)
                else:
                    action = encrypted_action[:30] + "..." if len(encrypted_action) > 30 else encrypted_action
                    details = encrypted_details[:30] + "..." if len(encrypted_details) > 30 else encrypted_details
                
                # Filtrování podle akce, pokud je zadáno
                if action_filter and action != action_filter:
                    continue
                
                logs.append({
                    'id': log_id,
                    'action': action,
                    'details': details,
                    'status': status,
                    'timestamp': timestamp
                })
            
            return logs
        except Exception as e:
            print(f"Chyba při čtení audit logu: {str(e)}")
            return []
    
    def get_system_audit_log(self, limit: int = 100, decrypt: bool = True) -> List[Dict]:
        """
        Získání systémového audit logu (všichni uživatelé)
        Dešifruje data jen pokud je dostupný user_key (tj. pro user-specific logy)
        """
        try:
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, user_id, action, details, status, timestamp, encrypted
                FROM audit_log
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            
            results = cursor.fetchall()
            DatabaseManager.close_connection(conn)
            
            logs = []
            for row in results:
                log_id, user_id, encrypted_action, encrypted_details, status, timestamp, encrypted_flag = row
                
                # Pokud je log šifrovaný (encrypted_flag=1), musíme vědět user_key
                # Pokud je plaintext (encrypted_flag=0), je to systémový log
                action = encrypted_action
                details = encrypted_details
                
                if decrypt and encrypted_flag and user_id:
                    # Dešifrování - načteme user_key
                    try:
                        users_conn = DatabaseManager.get_connection('users')
                        users_cursor = users_conn.cursor()
                        users_cursor.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
                        user_row = users_cursor.fetchone()
                        DatabaseManager.close_connection(users_conn)
                        
                        if user_row:
                            user_salt, password_hash = user_row[0], user_row[1]
                            user_key = self.crypto.derive_user_encryption_key(user_id, user_salt, password_hash)
                            action = self.crypto.decrypt_audit_data(encrypted_action, user_key)
                            details = self.crypto.decrypt_audit_data(encrypted_details, user_key)
                    except Exception:
                        # Pokud se nepodaří dešifrovat, ponech encrypted
                        pass
                
                logs.append({
                    'id': log_id,
                    'user_id': user_id,
                    'action': action[:30] + "..." if len(action) > 30 else action,
                    'details': details[:30] + "..." if len(details) > 30 else details,
                    'status': status,
                    'timestamp': timestamp
                })
            
            return logs
        except Exception as e:
            return []
    
    def get_failed_login_attempts(self, user_id: int, hours: int = 24) -> int:
        """Získání počtu neúspěšných pokusů o přihlášení"""
        try:
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM audit_log
                WHERE user_id = ? AND status = 'FAILED'
                AND timestamp > datetime('now', '-' || ? || ' hours')
            ''', (user_id, hours))
            
            result = cursor.fetchone()
            DatabaseManager.close_connection(conn)
            
            return result[0] if result else 0
        except Exception:
            return 0
    
    def get_security_events(self, hours: int = 24, decrypt: bool = True) -> List[Dict]:
        """Získání bezpečnostních událostí za poslední dobu"""
        try:
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, user_id, action, status, timestamp
                FROM audit_log
                WHERE timestamp > datetime('now', '-' || ? || ' hours')
                ORDER BY timestamp DESC
            ''', (hours,))
            
            results = cursor.fetchall()
            DatabaseManager.close_connection(conn)
            
            security_actions = ['LOGIN', '2FA_VERIFY', 'PASSWORD_VERIFY_FAILED', '2FA_ENABLE', 'PASSWORD_CHANGE']
            
            events = []
            for row in results:
                log_id, user_id, encrypted_action, status, timestamp = row
                
                # Dešifrování
                if decrypt:
                    action = self.crypto.decrypt_audit_data(encrypted_action)
                else:
                    action = encrypted_action[:20] + "..."
                
                # Filtrování bezpečnostních akcí
                if action in security_actions:
                    events.append({
                        'id': log_id,
                        'user_id': user_id,
                        'action': action,
                        'status': status,
                        'timestamp': timestamp
                    })
            
            return events
        except Exception:
            return []
    
    def get_audit_statistics(self) -> Dict:
        """Statistika audit logu"""
        try:
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            # Celkový počet záznamů
            cursor.execute('SELECT COUNT(*) FROM audit_log')
            total = cursor.fetchone()[0]
            
            # Počet úspěšných akcí
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE status = 'SUCCESS'")
            success = cursor.fetchone()[0]
            
            # Počet neúspěšných akcí
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE status = 'FAILED'")
            failed = cursor.fetchone()[0]
            
            # Počet uživatelů
            cursor.execute("SELECT COUNT(DISTINCT user_id) FROM audit_log")
            users = cursor.fetchone()[0]
            
            DatabaseManager.close_connection(conn)
            
            return {
                'total_records': total,
                'successful': success,
                'failed': failed,
                'success_rate': f"{(success/total*100):.1f}%" if total > 0 else "0%",
                'unique_users': users,
                'encryption': 'Fernet (AES-128-CBC)'
            }
        except Exception:
            return {}