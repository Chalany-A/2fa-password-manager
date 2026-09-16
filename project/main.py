# main.py
"""
Správce hesel s 2FA a auditováním
Vytvořeno pro předmět Aplikovaná kryptografie
"""

import sys
from PySide6.QtWidgets import QApplication
from gui_pyside6 import LoginWindow


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())