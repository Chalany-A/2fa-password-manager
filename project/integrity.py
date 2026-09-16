# integrity.py
"""
Kontrola integrity dat v různých databázích
"""

import sqlite3
from typing import Tuple, Dict, List
from datetime import datetime
from database import DatabaseManager
from audit import AuditManager


class IntegrityManager:
    """Správa kontroly integrity dat"""
    
    def __init__(self):
        self.audit = AuditManager()
    
    def check_user_integrity(self, user_id: int) -> Tuple[bool, str, Dict]:
        """
        Kontrola integrity dat uživatele
        Vrací (OK, zpráva, report)
        """
        try:
            report = {
                'checked_at': datetime.now().isoformat(),
                'databases_checked': [],
                'integrity_ok': True,
                'issues': [],
                'statistics': {}
            }
            
            # Kontrola v users DB
            conn_users = DatabaseManager.get_connection('users')
            try:
                cursor_users = conn_users.cursor()
                cursor_users.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
                user_data = cursor_users.fetchone()
                
                if not user_data:
                    report['integrity_ok'] = False
                    report['issues'].append("Uživatel nenalezen")
                    return False, "Uživatel nenalezen", report
                
                report['databases_checked'].append('users')
                report['statistics']['user'] = user_data[1]
            finally:
                DatabaseManager.close_connection(conn_users)
            
            # Kontrola v twofa DB
            conn_twofa = DatabaseManager.get_connection('twofa')
            try:
                cursor_twofa = conn_twofa.cursor()
                cursor_twofa.execute('SELECT id, enabled FROM two_factor_auth WHERE user_id = ?', (user_id,))
                twofa_data = cursor_twofa.fetchone()
                
                if twofa_data:
                    report['databases_checked'].append('twofa')
                    report['statistics']['2fa_enabled'] = bool(twofa_data[1])
                else:
                    report['issues'].append("2FA záznam nenalezen")
            finally:
                DatabaseManager.close_connection(conn_twofa)
            
            # Kontrola v passwords DB
            conn_pwd = DatabaseManager.get_connection('passwords')
            try:
                cursor_pwd = conn_pwd.cursor()
                cursor_pwd.execute('''
                    SELECT COUNT(*) FROM stored_passwords WHERE user_id = ?
                ''', (user_id,))
                password_count = cursor_pwd.fetchone()[0]
                report['databases_checked'].append('passwords')
                report['statistics']['passwords_stored'] = password_count
            finally:
                DatabaseManager.close_connection(conn_pwd)
            
            # Kontrola v audit DB
            conn_audit = DatabaseManager.get_connection('audit')
            try:
                cursor_audit = conn_audit.cursor()
                cursor_audit.execute('''
                    SELECT COUNT(*) FROM audit_log WHERE user_id = ?
                ''', (user_id,))
                audit_count = cursor_audit.fetchone()[0]
                report['statistics']['audit_log_entries'] = audit_count
                report['databases_checked'].append('audit (šifrovaný)')
            finally:
                DatabaseManager.close_connection(conn_audit)
            
            self.audit.log_action(
                user_id,
                "INTEGRITY_CHECK",
                f"Integrity OK: {report['integrity_ok']}",
                "SUCCESS"
            )
            
            return report['integrity_ok'], "Kontrola integrity dokončena", report
        
        except Exception as e:
            return False, f"Chyba při kontrole integrity: {str(e)}", {}
    
    def check_system_integrity(self) -> Tuple[bool, str, Dict]:
        """Kontrola systémové integrity"""
        try:
            report = {
                'checked_at': datetime.now().isoformat(),
                'databases': {},
                'integrity_ok': True,
                'issues': []
            }
            
            # Kontrola users DB
            conn_users = DatabaseManager.get_connection('users')
            try:
                cursor_users = conn_users.cursor()
                cursor_users.execute('SELECT COUNT(*) FROM users')
                user_count = cursor_users.fetchone()[0]
                report['databases']['users'] = user_count
            finally:
                DatabaseManager.close_connection(conn_users)
            
            # Kontrola twofa DB
            conn_twofa = DatabaseManager.get_connection('twofa')
            try:
                cursor_twofa = conn_twofa.cursor()
                cursor_twofa.execute('SELECT COUNT(*) FROM two_factor_auth')
                twofa_count = cursor_twofa.fetchone()[0]
                report['databases']['twofa'] = twofa_count
            finally:
                DatabaseManager.close_connection(conn_twofa)
            
            # Kontrola passwords DB
            conn_pwd = DatabaseManager.get_connection('passwords')
            try:
                cursor_pwd = conn_pwd.cursor()
                cursor_pwd.execute('SELECT COUNT(*) FROM stored_passwords')
                password_count = cursor_pwd.fetchone()[0]
                report['databases']['passwords'] = password_count
            finally:
                DatabaseManager.close_connection(conn_pwd)
            
            # Kontrola audit DB
            conn_audit = DatabaseManager.get_connection('audit')
            try:
                cursor_audit = conn_audit.cursor()
                cursor_audit.execute('SELECT COUNT(*) FROM audit_log')
                audit_count = cursor_audit.fetchone()[0]
                report['databases']['audit (šifrovaný)'] = audit_count
            finally:
                DatabaseManager.close_connection(conn_audit)
            
            return report['integrity_ok'], "Systémová kontrola integrity dokončena", report
        
        except Exception as e:
            return False, f"Chyba při kontrole systémové integrity: {str(e)}", {}
    
    def verify_password_integrity(self, user_id: int) -> Tuple[bool, str, Dict]:
        """
        Kontrola integrity všech hesel uživatele (HMAC tagy)
        HMAC je odvozený z user_key (user_id + user_salt + password_hash)
        Vrací (OK, zpráva, detaily)
        """
        try:
            from crypto import CryptoManager
            
            report = {
                'user_id': user_id,
                'checked_at': datetime.now().isoformat(),
                'passwords_checked': 0,
                'passwords_corrupted': 0,
                'corrupted_services': [],
                'all_ok': True
            }
            
            # Načtení user_salt a password_hash z users DB pro odvození user_key
            conn_users = DatabaseManager.get_connection('users')
            try:
                cursor_users = conn_users.cursor()
                cursor_users.execute('SELECT salt, password_hash FROM users WHERE id = ?', (user_id,))
                user_row = cursor_users.fetchone()
            finally:
                DatabaseManager.close_connection(conn_users)
            
            if not user_row:
                return False, "Uživatel nenalezen", report
            
            user_salt, password_hash = user_row[0], user_row[1]
            
            conn = DatabaseManager.get_connection('passwords')
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, service_name, password_hash, integrity_tag 
                    FROM stored_passwords WHERE user_id = ?
                ''', (user_id,))
                
                passwords = cursor.fetchall()
                
                for pwd in passwords:
                    pwd_id, service_name, encrypted_pwd, tag = pwd
                    report['passwords_checked'] += 1
                    
                    # Ověření HMAC integrity tagu s user_salt a password_hash
                    if not CryptoManager.verify_integrity_tag(encrypted_pwd, user_id, user_salt, password_hash, tag):
                        report['passwords_corrupted'] += 1
                        report['corrupted_services'].append(service_name)
                        report['all_ok'] = False
            finally:
                DatabaseManager.close_connection(conn)
            
            self.audit.log_action(
                user_id,
                "PASSWORD_INTEGRITY_CHECK",
                f"Zkontrolováno {report['passwords_checked']} hesel, problémů: {report['passwords_corrupted']}",
                "SUCCESS" if report['all_ok'] else "WARNING"
            )
            
            return report['all_ok'], f"Integrity: {report['passwords_checked']} OK, {report['passwords_corrupted']} poškozeno", report
        
        except Exception as e:
            return False, f"Chyba při ověřování integrity hesel: {str(e)}", {}