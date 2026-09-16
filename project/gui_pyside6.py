# gui_pyside6.py
"""
GUI pro správce hesel s 2FA - pomocí PySide6
Moderní, funkční a funguje na macOS!
"""

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QListWidget, QListWidgetItem,
    QMessageBox, QTextEdit, QDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QClipboard, QPixmap

from user import UserManager
from two_factor_auth import TwoFactorAuthManager
from password_manager import PasswordManager
from integrity import IntegrityManager
from audit import AuditManager
from database import DatabaseManager
from crypto import CryptoManager


class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Správce Hesel")
        self.setGeometry(100, 100, 500, 300)
        
        DatabaseManager.init_all_databases()
        self.user_mgr = UserManager()
        
        self.setup_ui()
    
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Správce Hesel s 2FA")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        # Username
        layout.addWidget(QLabel("Uživatelské jméno:"))
        self.username = QLineEdit()
        self.username.setPlaceholderText("Zadejte jméno...")
        layout.addWidget(self.username)
        
        # Password
        layout.addWidget(QLabel("Heslo:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Zadejte heslo...")
        self.password.returnPressed.connect(self.login)  # Enter = login
        layout.addWidget(self.password)
        
        # Tlačítka
        btn_layout = QHBoxLayout()
        
        btn_login = QPushButton("Přihlásit se")
        btn_login.clicked.connect(self.login)
        btn_login.setMinimumHeight(35)
        btn_layout.addWidget(btn_login)
        
        btn_register = QPushButton("Registrace")
        btn_register.clicked.connect(self.register)
        btn_register.setMinimumHeight(35)
        btn_layout.addWidget(btn_register)
        
        layout.addLayout(btn_layout)
        layout.addStretch()
        
        central.setLayout(layout)
    
    def login(self):
        user = self.username.text().strip()
        pwd = self.password.text().strip()
        
        if not user or not pwd:
            QMessageBox.warning(self, "Chyba", "Vyplňte všechna pole!")
            return
        
        success, msg, uid = self.user_mgr.login(user, pwd)
        
        if success:
            # Zkontroluj 2FA
            twofa_mgr = TwoFactorAuthManager()
            status = twofa_mgr.get_2fa_status(uid)
            
            if status['enabled']:
                # Zobraz 2FA dialog
                dialog = TwoFAVerifyDialog(uid)
                if dialog.exec() == QDialog.Accepted:
                    # 2FA ověřeno, jdi do dashboardu
                    self.dashboard_window = DashboardWindow(uid, user)
                    self.dashboard_window.show()
                    self.close()
                else:
                    QMessageBox.warning(self, "Chyba", "2FA ověření selhalo!")
                    self.password.clear()
                    self.password.setFocus()
            else:
                # Žádná 2FA, jdi rovnou do dashboardu
                self.dashboard_window = DashboardWindow(uid, user)
                self.dashboard_window.show()
                self.close()
        else:
            QMessageBox.critical(self, "Chyba", msg)
            self.password.clear()
            self.password.setFocus()
    
    def register(self):
        user = self.username.text().strip()
        pwd = self.password.text().strip()
        
        if not user or not pwd:
            QMessageBox.warning(self, "Chyba", "Vyplňte všechna pole!")
            return
        
        success, msg = self.user_mgr.register_user(user, pwd)
        
        if success:
            QMessageBox.information(self, "Úspěch", f"{msg}\n\nNyní se přihlaste!")
            self.username.clear()
            self.password.clear()
            self.username.setFocus()
        else:
            QMessageBox.critical(self, "Chyba", msg)
            self.password.clear()
            self.password.setFocus()


class DashboardWindow(QMainWindow):
    def __init__(self, user_id, username):
        super().__init__()
        self.user_id = user_id
        self.username = username
        
        self.setWindowTitle(f"Správce Hesel - {username}")
        self.setGeometry(100, 100, 700, 600)
        
        # Inicializace
        self.twofa_mgr = TwoFactorAuthManager()
        self.pwd_mgr = PasswordManager()
        self.integrity_mgr = IntegrityManager()
        self.audit_mgr = AuditManager()
        
        self.setup_ui()
    
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        
        # Header s odhlášením
        header = QHBoxLayout()
        header.addWidget(QLabel(f"Přihlášen: {self.username}"))
        header.addStretch()
        btn_logout = QPushButton("Odhlásit se")
        btn_logout.clicked.connect(self.logout)
        header.addWidget(btn_logout)
        layout.addLayout(header)
        
        # Tabs
        tabs = QTabWidget()
        
        # Tab 1: Hesla
        tab_passwords = self.create_passwords_tab()
        tabs.addTab(tab_passwords, "Hesla")
        
        # Tab 2: 2FA
        tab_2fa = self.create_2fa_tab()
        tabs.addTab(tab_2fa, "2FA")
        
        # Tab 3: Audit
        tab_audit = self.create_audit_tab()
        tabs.addTab(tab_audit, "Audit Log")
        
        layout.addWidget(tabs)
        central.setLayout(layout)
    
    def create_passwords_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Uložená hesla:"))
        
        # List hesel
        self.passwords_list = QListWidget()
        self.passwords_list.itemClicked.connect(self.show_password)
        self.load_passwords()
        layout.addWidget(self.passwords_list)
        
        # Zobrazení hesla
        layout.addWidget(QLabel("Heslo:"))
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        layout.addWidget(self.password_display)
        
        # Tlačítka
        btn_layout = QHBoxLayout()
        
        btn_copy = QPushButton("Zkopírovat")
        btn_copy.clicked.connect(self.copy_password)
        btn_layout.addWidget(btn_copy)
        
        btn_delete = QPushButton("Smazat")
        btn_delete.clicked.connect(self.delete_password)
        btn_layout.addWidget(btn_delete)
        
        layout.addLayout(btn_layout)
        
        # Nové heslo
        layout.addWidget(QLabel("\nPřidat nové heslo:"))
        
        layout.addWidget(QLabel("Název služby:"))
        self.service_input = QLineEdit()
        layout.addWidget(self.service_input)
        
        layout.addWidget(QLabel("Heslo:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        
        btn_save = QPushButton("Uložit heslo")
        btn_save.clicked.connect(self.save_password)
        layout.addWidget(btn_save)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def load_passwords(self):
        self.passwords_list.clear()
        try:
            passwords = self.pwd_mgr.get_password_list(self.user_id)
            if passwords:
                for p in passwords:
                    item = QListWidgetItem(f"{p['service']}")
                    self.passwords_list.addItem(item)
            else:
                item = QListWidgetItem("(Žádná hesla neuložena)")
                self.passwords_list.addItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Chyba", f"Chyba při načítání hesel: {str(e)}")
    
    def show_password(self):
        current_item = self.passwords_list.currentItem()
        
        if not current_item:
            self.password_display.clear()
            return
        
        service = current_item.text()
        
        if service == "(Žádná hesla neuložena)":
            self.password_display.clear()
            return
        
        try:
            # Dešifrování hesla ze šifrovaného uložiště
            password = self.pwd_mgr.get_password(self.user_id, service)
            if password:
                self.password_display.setText(password)
            else:
                self.password_display.clear()
        except Exception as e:
            QMessageBox.critical(self, "Chyba", f"Chyba při načítání hesla: {str(e)}")
            self.password_display.clear()
    
    def copy_password(self):
        pwd = self.password_display.text()
        
        if not pwd:
            QMessageBox.warning(self, "Chyba", "Nejdříve vyberte heslo!")
            return
        
        clipboard = QApplication.clipboard()
        clipboard.setText(pwd)
        QMessageBox.information(self, "Úspěch", "Heslo zkopírováno do schránky!")
    
    def delete_password(self):
        current_item = self.passwords_list.currentItem()
        
        if not current_item:
            QMessageBox.warning(self, "Chyba", "Vyberte heslo k smazání!")
            return
        
        service = current_item.text()
        
        if service == "(Žádná hesla neuložena)":
            return
        
        reply = QMessageBox.question(self, "Potvrzení", 
                                     f"Opravdu chcete smazat heslo pro '{service}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            success, msg = self.pwd_mgr.delete_password(self.user_id, service)
            
            if success:
                QMessageBox.information(self, "Úspěch", msg)
                self.password_display.clear()
                self.load_passwords()
            else:
                QMessageBox.critical(self, "Chyba", msg)
    
    def save_password(self):
        service = self.service_input.text().strip()
        pwd = self.password_input.text().strip()
        
        if not service or not pwd:
            QMessageBox.warning(self, "Chyba", "Vyplňte všechna pole!")
            return
        
        success, msg = self.pwd_mgr.save_password(self.user_id, service, pwd)
        
        if success:
            QMessageBox.information(self, "Úspěch", msg)
            self.service_input.clear()
            self.password_input.clear()
            self.load_passwords()
        else:
            QMessageBox.critical(self, "Chyba", msg)
    
    def create_2fa_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        status = self.twofa_mgr.get_2fa_status(self.user_id)
        status_text = "POVOLENO" if status['enabled'] else "ZAKÁZÁNO"
        
        layout.addWidget(QLabel(f"Status 2FA: {status_text}"))
        
        if not status['enabled']:
            layout.addWidget(QLabel("2FA není aktivní. Kliknutím na tlačítko níže ji nastavte."))
            
            btn_setup = QPushButton("Nastavit 2FA")
            btn_setup.clicked.connect(self.setup_2fa)
            btn_setup.setMinimumHeight(40)
            layout.addWidget(btn_setup)
        else:
            layout.addWidget(QLabel(
                f"2FA je aktivní. Zbývajících záložních kódů: {status['backup_codes_remaining']}"
            ))
            
            btn_disable = QPushButton("Deaktivovat 2FA")
            btn_disable.clicked.connect(self.disable_2fa)
            btn_disable.setMinimumHeight(40)
            layout.addWidget(btn_disable)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def setup_2fa(self):
        dialog = TwoFASetupDialog(self.user_id, self.username)
        if dialog.exec() == QDialog.Accepted:
            # Refresh 2FA tab
            self.setup_ui()
    
    def disable_2fa(self):
        reply = QMessageBox.question(self, "Potvrzení", 
                                     "Opravdu deaktivovat 2FA?",
                                     QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            success, msg = self.twofa_mgr.disable_2fa(self.user_id)
            QMessageBox.information(self, "Úspěch", msg)
            self.setup_ui()
    
    def create_audit_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Audit Log (posledních 20 záznamů):"))
        
        text = QTextEdit()
        text.setReadOnly(True)
        
        logs = self.audit_mgr.get_user_audit_log(self.user_id, limit=20, decrypt=True)
        
        content = ""
        for log in logs:
            content += f"[{log['status']}] {log['action']}\n"
            content += f"  └─ {log['details']}\n"
            content += f"  └─ {log['timestamp']}\n\n"
        
        text.setText(content if content else "Žádné záznamy")
        layout.addWidget(text)
        
        widget.setLayout(layout)
        return widget
    
    def logout(self):
        """Odhlášení a návrat na přihlašovací obrazovku"""
        reply = QMessageBox.question(self, "Potvrzení", 
                                     "Opravdu se chcete odhlásit?",
                                     QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Vytvoříme nové přihlašovací okno
            self.login_window = LoginWindow()
            self.login_window.show()
            self.close()


class TwoFAVerifyDialog(QDialog):
    """Dialog pro ověření 2FA při přihlášení"""
    def __init__(self, user_id):
        super().__init__()
        self.user_id = user_id
        self.twofa_mgr = TwoFactorAuthManager()
        self.setWindowTitle("Ověření 2FA")
        self.setGeometry(100, 100, 400, 200)
        self.setModal(True)
        
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Zadejte 6-místný TOTP kód:"))
        
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("000000")
        self.totp_input.setMaxLength(6)
        self.totp_input.returnPressed.connect(self.verify)
        layout.addWidget(self.totp_input)
        
        layout.addWidget(QLabel("nebo zadejte záložní kód:"))
        self.backup_input = QLineEdit()
        self.backup_input.setPlaceholderText("Záložní kód")
        layout.addWidget(self.backup_input)
        
        btn_layout = QHBoxLayout()
        
        btn_verify = QPushButton("Ověřit")
        btn_verify.clicked.connect(self.verify)
        btn_verify.setMinimumHeight(35)
        btn_layout.addWidget(btn_verify)
        
        btn_cancel = QPushButton("Zrušit")
        btn_cancel.clicked.connect(self.reject)
        btn_cancel.setMinimumHeight(35)
        btn_layout.addWidget(btn_cancel)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
    
    def verify(self):
        totp_code = self.totp_input.text().strip()
        backup_code = self.backup_input.text().strip()
        
        if totp_code:
            if len(totp_code) != 6 or not totp_code.isdigit():
                QMessageBox.warning(self, "Chyba", "TOTP kód musí mít 6 číslic!")
                return
            
            if self.twofa_mgr.verify_2fa(self.user_id, totp_code):
                self.accept()
            else:
                QMessageBox.critical(self, "Chyba", "Nesprávný TOTP kód!")
                self.totp_input.clear()
        
        elif backup_code:
            if self.twofa_mgr.verify_backup_code(self.user_id, backup_code):
                self.accept()
            else:
                QMessageBox.critical(self, "Chyba", "Neplatný záložní kód!")
                self.backup_input.clear()
        else:
            QMessageBox.warning(self, "Chyba", "Zadejte TOTP kód nebo záložní kód!")


class TwoFASetupDialog(QDialog):
    """Dialog pro nastavení 2FA s QR kódem"""
    def __init__(self, user_id, username):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.twofa_mgr = TwoFactorAuthManager()
        
        self.setWindowTitle("Nastavení 2FA")
        self.setGeometry(100, 100, 600, 700)
        self.setModal(True)
        
        self.secret_key = None
        self.backup_codes = None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Nastavení dvoustupňové autentizace"))
        
        # Setup
        success, msg, secret = self.twofa_mgr.setup_2fa(self.user_id)
        if not success:
            QMessageBox.critical(self, "Chyba", msg)
            self.reject()
            return
        
        self.secret_key = secret
        
        layout.addWidget(QLabel("Krok 1: Naskenujte QR kód"))
        
        # QR kód
        qr_base64 = self.twofa_mgr.generate_qr_code(self.user_id, self.username)
        if qr_base64:
            pixmap = QPixmap()
            pixmap.loadFromData(__import__('base64').b64decode(qr_base64))
            qr_label = QLabel()
            qr_label.setPixmap(pixmap.scaledToWidth(300))
            layout.addWidget(qr_label)
        
        layout.addWidget(QLabel("Nebo zadejte manuálně:"))
        secret_display = QLineEdit()
        secret_display.setText(secret)
        secret_display.setReadOnly(True)
        layout.addWidget(secret_display)
        
        # Ověření TOTP
        layout.addWidget(QLabel("\nKrok 2: Zadejte 6-místný kód z aplikace"))
        self.totp_verify_input = QLineEdit()
        self.totp_verify_input.setPlaceholderText("000000")
        self.totp_verify_input.setMaxLength(6)
        layout.addWidget(self.totp_verify_input)
        
        # Info
        layout.addWidget(QLabel(
            "Používejte aplikaci jako Google Authenticator, Authy nebo Microsoft Authenticator"
        ))
        
        # Tlačítka
        btn_layout = QHBoxLayout()
        
        btn_enable = QPushButton("Aktivovat 2FA")
        btn_enable.clicked.connect(self.enable)
        btn_enable.setMinimumHeight(35)
        btn_layout.addWidget(btn_enable)
        
        btn_cancel = QPushButton("Zrušit")
        btn_cancel.clicked.connect(self.reject)
        btn_cancel.setMinimumHeight(35)
        btn_layout.addWidget(btn_cancel)
        
        layout.addLayout(btn_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def enable(self):
        totp_code = self.totp_verify_input.text().strip()
        
        if not totp_code or len(totp_code) != 6 or not totp_code.isdigit():
            QMessageBox.warning(self, "Chyba", "Zadejte 6-místný TOTP kód!")
            return
        
        success, msg, backup_codes = self.twofa_mgr.enable_2fa(self.user_id, totp_code)
        
        if success:
            dialog = BackupCodesDialog(backup_codes)
            dialog.exec()
            self.accept()
        else:
            QMessageBox.critical(self, "Chyba", msg)


class BackupCodesDialog(QDialog):
    """Dialog pro zobrazení záložních kódů"""
    def __init__(self, backup_codes):
        super().__init__()
        self.setWindowTitle("Záložní kódy")
        self.setGeometry(100, 100, 500, 400)
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Uložte si tyto kódy na bezpečné místo!"))
        layout.addWidget(QLabel("Každý kód lze použít pouze jednou místo TOTP kódu."))
        
        text = QTextEdit()
        text.setReadOnly(True)
        text.setText("\n".join(backup_codes))
        layout.addWidget(text)
        
        btn_layout = QHBoxLayout()
        
        btn_copy = QPushButton("Zkopírovat")
        btn_copy.clicked.connect(lambda: self.copy_codes(backup_codes))
        btn_copy.setMinimumHeight(35)
        btn_layout.addWidget(btn_copy)
        
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self.accept)
        btn_ok.setMinimumHeight(35)
        btn_layout.addWidget(btn_ok)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
    
    def copy_codes(self, codes):
        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(codes))
        QMessageBox.information(self, "Úspěch", "Kódy zkopírované do schránky!")


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    
    window = LoginWindow()
    window.show()
    
    sys.exit(app.exec())
