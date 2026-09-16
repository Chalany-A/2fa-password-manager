# database.py
"""
Inicializace a správa více databází
"""

import sqlite3
from typing import Optional, List, Dict, Any
from config import DATABASES


class DatabaseManager:
    """Správa více databází"""
    
    @staticmethod
    def init_users_db():
        """Inicializace databáze uživatelů"""
        try:
            conn = sqlite3.connect(DATABASES['users'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Chyba při inicializaci users DB: {e}")
            raise
    
    @staticmethod
    def init_passwords_db():
        """Inicializace databáze hesel"""
        try:
            conn = sqlite3.connect(DATABASES['passwords'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS stored_passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    integrity_tag TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Chyba při inicializaci passwords DB: {e}")
            raise
    
    @staticmethod
    def init_twofa_db():
        """Inicializace databáze 2FA"""
        try:
            conn = sqlite3.connect(DATABASES['twofa'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS two_factor_auth (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE NOT NULL,
                    secret_key TEXT NOT NULL,
                    backup_codes TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 0,
                    last_totp_code TEXT,
                    last_totp_time INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Chyba při inicializaci 2FA DB: {e}")
            raise
    
    @staticmethod
    def init_audit_db():
        """Inicializace databáze auditu se šifrováním"""
        try:
            conn = sqlite3.connect(DATABASES['audit'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    encrypted BOOLEAN DEFAULT 1,
                    operation_nonce TEXT UNIQUE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS backup_codes_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    code TEXT NOT NULL,
                    used_at TIMESTAMP,
                    UNIQUE(user_id, code)
                )
            ''')
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Chyba při inicializaci audit DB: {e}")
            raise
    
    @staticmethod
    def init_all_databases():
        """Inicializace všech databází"""
        DatabaseManager.init_users_db()
        DatabaseManager.init_passwords_db()
        DatabaseManager.init_twofa_db()
        DatabaseManager.init_audit_db()
    
    @staticmethod
    def get_connection(db_type: str) -> sqlite3.Connection:
        """Vytvoření připojení k databázi"""
        if db_type not in DATABASES:
            raise ValueError(f"Neznámá databáze: {db_type}")
        conn = sqlite3.connect(DATABASES[db_type])
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def close_connection(conn: sqlite3.Connection):
        """Zavření připojení k databázi"""
        if conn:
            conn.close()
    
    # CRUD operace - uživatelé
    @staticmethod
    def insert_user(username: str, password_hash: str, salt: str) -> int:
        """Vložení nového uživatele, vrací ID"""
        try:
            conn = DatabaseManager.get_connection('users')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            ''', (username, password_hash, salt))
            
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return user_id
        except sqlite3.Error as e:
            print(f"Chyba při vkládání uživatele: {e}")
            raise
    
    @staticmethod
    def get_user(username: str) -> Optional[Dict[str, Any]]:
        """Získání uživatele podle jména"""
        try:
            conn = DatabaseManager.get_connection('users')
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            conn.close()
            
            return dict(result) if result else None
        except sqlite3.Error as e:
            print(f"Chyba při čtení uživatele: {e}")
            raise
    
    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
        """Získání uživatele podle ID"""
        try:
            conn = DatabaseManager.get_connection('users')
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()
            conn.close()
            
            return dict(result) if result else None
        except sqlite3.Error as e:
            print(f"Chyba při čtení uživatele podle ID: {e}")
            raise
    
    # CRUD operace - hesla
    @staticmethod
    def insert_password(user_id: int, service_name: str, password_hash: str, salt: str) -> int:
        """Vložení nového hesla, vrací ID"""
        try:
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO stored_passwords (user_id, service_name, password_hash, salt)
                VALUES (?, ?, ?, ?)
            ''', (user_id, service_name, password_hash, salt))
            
            conn.commit()
            pwd_id = cursor.lastrowid
            conn.close()
            return pwd_id
        except sqlite3.Error as e:
            print(f"Chyba při vkládání hesla: {e}")
            raise
    
    @staticmethod
    def get_user_passwords(user_id: int) -> List[Dict[str, Any]]:
        """Získání všech hesel uživatele"""
        try:
            conn = DatabaseManager.get_connection('passwords')
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM stored_passwords WHERE user_id = ?', (user_id,))
            results = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in results]
        except sqlite3.Error as e:
            print(f"Chyba při čtení hesel: {e}")
            raise
    
    # CRUD operace - audit
    @staticmethod
    def insert_audit_log(user_id: Optional[int], action: str, details: str, 
                        status: str, ip_address: Optional[str] = None) -> int:
        """Vložení záznamu do audit logu, vrací ID"""
        try:
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO audit_log (user_id, action, details, status, ip_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action, details, status, ip_address))
            
            conn.commit()
            log_id = cursor.lastrowid
            conn.close()
            return log_id
        except sqlite3.Error as e:
            print(f"Chyba při vkládání do audit logu: {e}")
            raise
    
    @staticmethod
    def get_audit_logs(user_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Získání audit logů, volitelně filtrované podle user_id"""
        try:
            conn = DatabaseManager.get_connection('audit')
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute('''
                    SELECT * FROM audit_log WHERE user_id = ?
                    ORDER BY timestamp DESC LIMIT ?
                ''', (user_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM audit_log
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            
            results = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in results]
        except sqlite3.Error as e:
            print(f"Chyba při čtení audit logů: {e}")
            raise