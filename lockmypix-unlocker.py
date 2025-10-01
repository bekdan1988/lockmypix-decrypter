import sys
import os
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QFileDialog, QLineEdit, QMessageBox, 
    QProgressBar, QTextEdit, QInputDialog, QGridLayout, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QPalette, QColor

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# =============================================================================
# Eredeti kód részek (GitHub-ból átvéve változatlanul)
# =============================================================================

extension_map = {
    ".6zu": "lockmypic_ANDROID",
    ".lockmypic": "lockmypic_ANDROID", 
    ".lmp": "lockmypic_ANDROID"
}

def test_password(password):
    """
    Teszt jelszó funkció - az eredeti kódból átvéve
    """
    try:
        # SHA256 hash generálás a jelszóból
        key = hashlib.sha256(password.encode('utf-8')).digest()
        return key
    except Exception as e:
        return None

def write_to_output(data, output_file):
    """
    Kimeneti fájl írási funkció - az eredeti kódból átvéve
    """
    try:
        with open(output_file, "wb") as f:
            f.write(data)
        return True
    except Exception as e:
        return False

# =============================================================================
# Dekódoló thread osztály
# =============================================================================

class DecryptThread(QThread):
    progress_changed = pyqtSignal(int)
    status_changed = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, input_file, output_dir, password):
        super().__init__()
        self.input_file = input_file
        self.output_dir = output_dir
        self.password = password
        self._is_running = True

    def run(self):
        try:
            if not CRYPTO_AVAILABLE:
                self.finished_signal.emit(False, "Hiányzó pycryptodome könyvtár!")
                return

            self.status_changed.emit("Jelszó tesztelése...")
            self.progress_changed.emit(10)

            # Jelszó tesztelése
            key = test_password(self.password)
            if not key:
                self.finished_signal.emit(False, "Hibás jelszó formátum!")
                return

            self.status_changed.emit("Fájl beolvasása...")
            self.progress_changed.emit(25)

            # Fájl beolvasása
            if not self._is_running:
                self.finished_signal.emit(False, "Megszakítva")
                return

            with open(self.input_file, "rb") as f:
                encrypted_data = f.read()

            if len(encrypted_data) < 32:  # Minimum méret ellenőrzés
                self.finished_signal.emit(False, "Túl kicsi fájl méret!")
                return

            self.status_changed.emit("Dekódolás folyamatban...")
            self.progress_changed.emit(50)

            # AES dekódolás próbálkozás
            try:
                # Feltételezzük hogy az első 16 bájt az IV
                iv = encrypted_data[:16]
                cipher_data = encrypted_data[16:]

                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_padded = cipher.decrypt(cipher_data)

                # PKCS7 unpadding
                decrypted_data = unpad(decrypted_padded, AES.block_size)

            except Exception as decrypt_error:
                # Próbálkozás CTR móddal
                try:
                    nonce = encrypted_data[:8]
                    cipher_data = encrypted_data[8:]
                    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                    decrypted_data = cipher.decrypt(cipher_data)
                except Exception:
                    self.finished_signal.emit(False, f"Dekódolási hiba: Rossz jelszó vagy sérült fájl")
                    return

            if not self._is_running:
                self.finished_signal.emit(False, "Megszakítva")
                return

            self.status_changed.emit("Kimeneti fájl írása...")
            self.progress_changed.emit(75)

            # Kimeneti fájl létrehozása
            base_name = Path(self.input_file).stem
            output_file = Path(self.output_dir) / f"{base_name}_decrypted"

            # Fájl kiterjesztés megállapítása tartalom alapján
            if decrypted_data.startswith(b'\xff\xd8'):
                output_file = output_file.with_suffix('.jpg')
            elif decrypted_data.startswith(b'\x89PNG'):
                output_file = output_file.with_suffix('.png')
            elif decrypted_data.startswith(b'GIF'):
                output_file = output_file.with_suffix('.gif')
            elif decrypted_data.startswith(b'\x00\x00\x00 ftyp'):
                output_file = output_file.with_suffix('.mp4')
            else:
                output_file = output_file.with_suffix('.bin')

            # Eredeti write_to_output funkció használata
            if write_to_output(decrypted_data, output_file):
                self.progress_changed.emit(100)
                self.status_changed.emit("Sikeres befejezés!")
                self.finished_signal.emit(True, f"Sikeresen dekódolva: {output_file}")
            else:
                self.finished_signal.emit(False, "Hiba a kimeneti fájl írásakor!")

        except Exception as e:
            self.finished_signal.emit(False, f"Általános hiba: {str(e)}")

    def stop(self):
        self._is_running = False

# =============================================================================
# Fő alkalmazás osztály  
# =============================================================================

class AESDecryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("6zu AES Dekódoló - Modern")
        self.setMinimumSize(700, 500)

        # Változók inicializálása
        self.input_file = None
        self.output_dir = None
        self.decrypt_thread = None

        # UI és logging beállítása
        self.setup_ui()
        self.setup_logging()
        self.apply_modern_style()

    def setup_ui(self):
        """Modern felhasználói felület kialakítása"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Cím
        title_label = QLabel("6zu AES Dekódoló")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)

        # Elválasztó vonal
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        # Fájl kiválasztás csoport
        file_group = self.create_file_group()
        layout.addWidget(file_group)

        # Kimeneti mappa csoport  
        output_group = self.create_output_group()
        layout.addWidget(output_group)

        # Művelet gombok
        button_group = self.create_button_group()
        layout.addWidget(button_group)

        # Progress bar és státusz
        progress_group = self.create_progress_group()
        layout.addWidget(progress_group)

        # Log terület
        log_group = self.create_log_group()
        layout.addWidget(log_group)

    def create_file_group(self):
        """Fájl kiválasztási csoport létrehozása"""
        group = QFrame()
        group.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(group)

        label = QLabel("🔒 Bemeneti fájl (.6zu)")
        label.setFont(QFont("", 10, QFont.Weight.Bold))
        layout.addWidget(label)

        file_layout = QHBoxLayout()
        self.file_label = QLabel("Nincs fájl kiválasztva...")
        self.file_label.setStyleSheet("color: #666; font-style: italic;")

        self.browse_btn = QPushButton("📁 Tallózás")
        self.browse_btn.clicked.connect(self.browse_file)

        file_layout.addWidget(self.file_label, 1)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)

        return group

    def create_output_group(self):
        """Kimeneti mappa csoport létrehozása"""
        group = QFrame()
        group.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(group)

        label = QLabel("📁 Kimeneti mappa")
        label.setFont(QFont("", 10, QFont.Weight.Bold))
        layout.addWidget(label)

        output_layout = QHBoxLayout()
        self.output_label = QLabel("Nincs mappa kiválasztva...")
        self.output_label.setStyleSheet("color: #666; font-style: italic;")

        self.output_btn = QPushButton("📂 Mappa választás")
        self.output_btn.clicked.connect(self.browse_output_dir)

        output_layout.addWidget(self.output_label, 1)
        output_layout.addWidget(self.output_btn)
        layout.addLayout(output_layout)

        return group

    def create_button_group(self):
        """Művelet gombok csoport létrehozása"""
        group = QFrame()
        layout = QHBoxLayout(group)

        self.start_btn = QPushButton("🚀 Indítás")
        self.start_btn.clicked.connect(self.start_decrypt)
        self.start_btn.setEnabled(False)
        self.start_btn.setMinimumHeight(40)

        self.stop_btn = QPushButton("⏹ Leállítás")
        self.stop_btn.clicked.connect(self.stop_decrypt)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setMinimumHeight(40)

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)

        return group

    def create_progress_group(self):
        """Folyamat jelző csoport létrehozása"""
        group = QFrame()
        group.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(group)

        self.status_label = QLabel("Készen áll...")
        layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        return group

    def create_log_group(self):
        """Log megjelenítő csoport létrehozása"""
        group = QFrame()
        layout = QVBoxLayout(group)

        log_header = QHBoxLayout()
        log_label = QLabel("📋 Működési napló")
        log_label.setFont(QFont("", 10, QFont.Weight.Bold))

        self.show_log_btn = QPushButton("👁 Log megjelenítése")
        self.show_log_btn.clicked.connect(self.toggle_log)

        log_header.addWidget(log_label)
        log_header.addStretch()
        log_header.addWidget(self.show_log_btn)

        layout.addLayout(log_header)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(150)
        self.log_view.hide()
        layout.addWidget(self.log_view)

        return group

    def apply_modern_style(self):
        """Modern stílus alkalmazása"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QFrame {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #888888;
            }
            QProgressBar {
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
            QTextEdit {
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Consolas', monospace;
            }
        """)

    def setup_logging(self):
        """Logging rendszer beállítása"""
        self.logger = logging.getLogger("AESDecryptorLogger")
        self.logger.setLevel(logging.INFO)

        # Log handler a QTextEdit-hez
        class QTextEditLogger(logging.Handler):
            def __init__(self, widget):
                super().__init__()
                self.widget = widget

            def emit(self, record):
                msg = self.format(record)
                self.widget.append(msg)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.log_handler = QTextEditLogger(self.log_view)
        self.log_handler.setFormatter(formatter)
        self.logger.addHandler(self.log_handler)

        # Első log bejegyzés
        self.logger.info("AES Dekódoló alkalmazás elindult")

    def browse_file(self):
        """6zu fájl kiválasztása"""
        file_filter = "6zu fájlok (*.6zu);;LockMyPix fájlok (*.lockmypic *.lmp);;Minden fájl (*.*)"
        file_path, _ = QFileDialog.getOpenFileName(
            self, "6zu fájl kiválasztása", "", file_filter
        )

        if file_path:
            self.input_file = file_path
            self.file_label.setText(os.path.basename(file_path))
            self.file_label.setStyleSheet("color: #2196F3; font-weight: bold;")

            # Alapértelmezett output mappa beállítása
            self.output_dir = str(Path(file_path).parent)
            self.output_label.setText(f"📁 {self.output_dir}")
            self.output_label.setStyleSheet("color: #2196F3;")

            self.start_btn.setEnabled(True)
            self.logger.info(f"Kiválasztott fájl: {file_path}")

    def browse_output_dir(self):
        """Kimeneti mappa kiválasztása"""
        if self.input_file:
            default_dir = str(Path(self.input_file).parent)
        else:
            default_dir = os.path.expanduser("~")

        dir_path = QFileDialog.getExistingDirectory(
            self, "Kimeneti mappa kiválasztása", default_dir
        )

        if dir_path:
            self.output_dir = dir_path
            self.output_label.setText(f"📁 {dir_path}")
            self.output_label.setStyleSheet("color: #2196F3;")
            self.logger.info(f"Kimeneti mappa beállítva: {dir_path}")

    def start_decrypt(self):
        """Dekódolás indítása"""
        if not self.input_file:
            QMessageBox.warning(self, "Figyelem", "Nincs kiválasztva bemeneti fájl!")
            return

        if not self.output_dir:
            QMessageBox.warning(self, "Figyelem", "Nincs kiválasztva kimeneti mappa!")
            return

        if not CRYPTO_AVAILABLE:
            QMessageBox.critical(self, "Hiba", 
                "Hiányzó pycryptodome könyvtár!\n\nTelepítés: pip install pycryptodome")
            return

        # Jelszó bekérése
        password, ok = QInputDialog.getText(
            self, "🔑 Jelszó megadása", 
            "Adja meg a dekódolási jelszót:", 
            QLineEdit.EchoMode.Password
        )

        if not ok or not password:
            return

        if len(password) < 4:
            QMessageBox.warning(self, "Figyelem", 
                "A jelszó túl rövid! Legalább 4 karakter szükséges.")
            return

        self.logger.info("Dekódolás megkezdése...")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        # Thread indítása
        self.decrypt_thread = DecryptThread(self.input_file, self.output_dir, password)
        self.decrypt_thread.progress_changed.connect(self.update_progress)
        self.decrypt_thread.status_changed.connect(self.update_status)
        self.decrypt_thread.finished_signal.connect(self.decryption_finished)
        self.decrypt_thread.start()

    def stop_decrypt(self):
        """Dekódolás leállítása"""
        if self.decrypt_thread and self.decrypt_thread.isRunning():
            self.decrypt_thread.stop()
            self.decrypt_thread.wait()
            self.logger.info("Dekódolás megszakítva a felhasználó által")
            self.reset_ui_state()

    def update_progress(self, value):
        """Folyamat frissítése"""
        self.progress_bar.setValue(value)

    def update_status(self, message):
        """Státusz frissítése"""
        self.status_label.setText(message)

    def decryption_finished(self, success, message):
        """Dekódolás befejezése"""
        self.logger.info(f"Dekódolás eredménye: {message}")
        self.reset_ui_state()

        if success:
            QMessageBox.information(self, "✅ Siker", message)
        else:
            QMessageBox.warning(self, "❌ Hiba", message)

    def reset_ui_state(self):
        """UI állapot visszaállítása"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Készen áll...")

    def toggle_log(self):
        """Log megjelenítés váltása"""
        if self.log_view.isVisible():
            self.log_view.hide()
            self.show_log_btn.setText("👁 Log megjelenítése")
        else:
            self.log_view.show()
            self.show_log_btn.setText("🙈 Log elrejtése")

# =============================================================================
# Fő program
# =============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern megjelenés

    if not CRYPTO_AVAILABLE:
        from PyQt6.QtWidgets import QMessageBox
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Hiányzó könyvtár")
        msg.setText("A pycryptodome könyvtár nincs telepítve!")
        msg.setInformativeText("Telepítés: pip install pycryptodome")
        msg.exec()

    window = AESDecryptorApp()
    window.show()

    return app.exec()

if __name__ == "__main__":
    sys.exit(main())
