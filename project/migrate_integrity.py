#!/usr/bin/env python3
"""
Migration script - Přidání integrity_tag sloupce bez ztráty dat
Zachová všechna hesla a přidá HMAC integrity tagy
"""

import sqlite3
from database import DatabaseManager
from crypto import CryptoManager
from config import DATABASES

def migrate_passwords_db():
    """Přidá integrity_tag sloupec k existující tabulce passwords"""
    
    conn = DatabaseManager.get_connection('passwords')
    cursor = conn.cursor()
    
    try:
        # Kontrola, zda sloupec již existuje
        cursor.execute("PRAGMA table_info(stored_passwords)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'integrity_tag' in columns:
            print("Sloupec integrity_tag již existuje")
            return True
        
        print("Migrace: Přidávám integrity_tag sloupec...")
        
        # Přidání nového sloupce s default hodnotou
        cursor.execute('''
            ALTER TABLE stored_passwords 
            ADD COLUMN integrity_tag TEXT DEFAULT 'PENDING'
        ''')
        print("Sloupec přidán")
        
        # Stažení všech hesel s salt a password_hash
        cursor_users = DatabaseManager.get_connection('users').cursor()
        cursor.execute('SELECT id, user_id, password_hash, salt FROM stored_passwords')
        passwords = cursor.fetchall()
        
        print(f"Generování integrity tagů pro {len(passwords)} hesel...")
        
        # Generování a aktualizace integrity tagů
        for pwd_id, user_id, encrypted_password, salt in passwords:
            # Načtení password_hash uživatele
            cursor_users.execute('SELECT password_hash, salt FROM users WHERE id = ?', (user_id,))
            user_data = cursor_users.fetchone()
            if user_data:
                password_hash, user_salt = user_data[0], user_data[1]
                tag = CryptoManager.generate_integrity_tag(encrypted_password, user_id, user_salt, password_hash)
                cursor.execute('''
                    UPDATE stored_passwords 
                    SET integrity_tag = ? 
                    WHERE id = ?
                ''', (tag, pwd_id))
        
        conn.commit()
        print(f"Aktualizováno {len(passwords)} hesel s integrity tagy")
        
        DatabaseManager.close_connection(conn)
        print("\nMigrace úspěšná! Všechna hesla zachována.")
        return True
    
    except sqlite3.OperationalError as e:
        print(f"Chyba: {e}")
        DatabaseManager.close_connection(conn)
        return False
    except Exception as e:
        print(f"Chyba při migraci: {e}")
        DatabaseManager.close_connection(conn)
        return False

if __name__ == "__main__":
    print("=== Password Integrity Migration ===\n")
    success = migrate_passwords_db()
    exit(0 if success else 1)
