
import sys
import os
import hashlib
import binascii
import threading
import time
from pathlib import Path
from datetime import datetime
import logging

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QFileDialog, 
                             QTextEdit, QProgressBar, QLineEdit, QMessageBox,
                             QGroupBox, QSpacerItem, QSizePolicy)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor

from Crypto.Cipher import AES
from Crypto.Util import Counter

class DecryptWorker(QThread):
    """Munkaszál a dekriptáláshoz"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, password, input_dir, output_dir):
        super().__init__()
        self.password = password
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.should_stop = False

        # Extension mapping ugyanaz mint az eredeti kódban
        self.extension_map = {
            ".vp3": ".mp4", ".vo1": ".webm", ".v27": ".mpg", ".vb9": ".avi",
            ".v77": ".mov", ".v78": ".wmv", ".v82": ".dv", ".vz9": ".divx",
            ".vi3": ".ogv", ".v1u": ".h261", ".v6m": ".h264", ".6zu": ".jpg",
            ".tr7": ".gif", ".p5o": ".png", ".8ur": ".bmp", ".33t": ".tiff",
            ".20i": ".webp", ".v93": ".heic", ".v91": ".flv", ".v80": ".3gpp",
            ".vo4": ".ts", ".v99": ".mkv", ".vr2": ".mpeg", ".vv3": ".dpg",
            ".v81": ".rmvb", ".vz8": ".vob", ".wi2": ".asf", ".vi4": ".h263",
            ".v2u": ".f4v", ".v76": ".m4v", ".v75": ".ram", ".v74": ".rm",
            ".v3u": ".mts", ".v92": ".dng", ".r89": ".ps", ".v79": ".3gp",
        }

    def test_password(self):
        """Jelszó tesztelése egy .6zu fájlon"""
        try:
            for file in os.listdir(self.input_dir):
                if file.endswith(".6zu"):
                    key = hashlib.sha1(self.password.encode()).digest()[:16]
                    iv = key
                    counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
                    encrypted_path = os.path.join(self.input_dir, file)

                    with open(encrypted_path, "rb") as enc_data:
                        dec_data = cipher.decrypt(enc_data.read(16))
                        header = binascii.hexlify(dec_data).decode("utf8")
                        if header.startswith("ffd8ff"):
                            return True
                        else:
                            return False
            return False
        except Exception as e:
            self.status_updated.emit(f"Hiba a jelszó tesztelésében: {str(e)}")
            return False

    def stop(self):
        """Megszakítás jelzése"""
        self.should_stop = True

    def run(self):
        """Fő dekriptálási folyamat"""
        try:
            # Jelszó tesztelése
            self.status_updated.emit("Jelszó tesztelése...")
            if not self.test_password():
                self.finished.emit(False, "Helytelen jelszó!")
                return

            self.status_updated.emit("Jelszó helyes, dekriptálás kezdése...")

            # Kulcs generálása
            key = hashlib.sha1(self.password.encode()).digest()[:16]
            iv = key

            # Kimeneti mappa létrehozása ha nem létezik
            if not Path(self.output_dir).exists():
                os.makedirs(self.output_dir)
                self.status_updated.emit(f"Kimeneti mappa létrehozva: {self.output_dir}")

            # Fájlok listázása
            files = [f for f in os.listdir(self.input_dir) if os.path.isfile(os.path.join(self.input_dir, f))]
            total_files = len(files)

            if total_files == 0:
                self.finished.emit(False, "Nincsenek feldolgozható fájlok a bemeneti mappában!")
                return

            processed_files = 0
            successful_files = 0

            for file in files:
                if self.should_stop:
                    self.status_updated.emit("Műveletek megszakítva!")
                    self.finished.emit(False, "Művelet megszakítva a felhasználó által")
                    return

                try:
                    encrypted_path = os.path.join(self.input_dir, file)
                    self.status_updated.emit(f"Feldolgozás: {file}")

                    # Új cipher objektum minden fájlhoz
                    counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

                    with open(encrypted_path, "rb") as enc_data:
                        dec_data = cipher.decrypt(enc_data.read())

                        # Fájlnév és kiterjesztés kezelése
                        basename, ext = os.path.splitext(file)
                        if ext in self.extension_map:
                            new_filename = basename + self.extension_map[ext]
                        else:
                            new_filename = file + ".unknown"

                        output_path = os.path.join(self.output_dir, new_filename)

                        with open(output_path, "wb") as output_file:
                            output_file.write(dec_data)

                        successful_files += 1
                        self.status_updated.emit(f"Sikeresen dekriptálva: {new_filename}")

                except Exception as e:
                    self.status_updated.emit(f"Hiba a fájl feldolgozásakor {file}: {str(e)}")

                processed_files += 1
                progress = int((processed_files / total_files) * 100)
                self.progress_updated.emit(progress)

            self.finished.emit(True, f"Dekriptálás befejezve! {successful_files}/{total_files} fájl sikeresen dekriptálva.")

        except Exception as e:
            self.finished.emit(False, f"Kritikus hiba: {str(e)}")


class LockMyPixDecryptor(QMainWindow):
    """Fő alkalmazás ablak"""

    def __init__(self):
        super().__init__()
        self.worker = None
        self.log_file = None
        self.setup_logging()
        self.init_ui()

    def setup_logging(self):
        """Naplózás beállítása"""
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(log_dir, f"decrypt_log_{timestamp}.log")

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

    def init_ui(self):
        """Felhasználói felület inicializálása"""
        self.setWindowTitle("LockMyPix Dekriptor v1.0")
        self.setGeometry(300, 300, 800, 600)
        self.setStyleSheet(self.get_modern_style())

        # Központi widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Fő layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(30, 30, 30, 30)

        # Cím
        title_label = QLabel("🔓 LockMyPix Fájl Dekriptor")
        title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; margin-bottom: 20px;")
        main_layout.addWidget(title_label)

        # Fájl műveletek csoport
        file_group = QGroupBox("📁 Mappa beállítások")
        file_layout = QVBoxLayout(file_group)

        # Bemeneti mappa
        input_layout = QHBoxLayout()
        input_label = QLabel("Bemeneti mappa (.6zu fájlok):")
        input_label.setMinimumWidth(200)
        self.input_path_edit = QLineEdit()
        self.input_path_edit.setPlaceholderText("Válasszon mappát a titkosított fájlokkal...")
        self.input_browse_btn = QPushButton("📂 Tallózás")
        self.input_browse_btn.clicked.connect(self.browse_input_folder)

        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_path_edit)
        input_layout.addWidget(self.input_browse_btn)
        file_layout.addLayout(input_layout)

        # Kimeneti mappa
        output_layout = QHBoxLayout()
        output_label = QLabel("Kimeneti mappa:")
        output_label.setMinimumWidth(200)
        self.output_path_edit = QLineEdit()
        self.output_path_edit.setPlaceholderText("Dekriptált fájlok mentési helye...")
        self.output_browse_btn = QPushButton("📂 Tallózás")
        self.output_browse_btn.clicked.connect(self.browse_output_folder)

        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_path_edit)
        output_layout.addWidget(self.output_browse_btn)
        file_layout.addLayout(output_layout)

        main_layout.addWidget(file_group)

        # Vezérlő gombok csoport
        control_group = QGroupBox("🎛️ Vezérlés")
        control_layout = QHBoxLayout(control_group)

        self.start_btn = QPushButton("▶️ Indítás")
        self.start_btn.clicked.connect(self.start_decryption)
        self.start_btn.setMinimumHeight(50)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)

        self.stop_btn = QPushButton("⏹️ Leállítás")
        self.stop_btn.clicked.connect(self.stop_decryption)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setMinimumHeight(50)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)

        self.log_btn = QPushButton("📋 Napló megnyitása")
        self.log_btn.clicked.connect(self.open_log)
        self.log_btn.setMinimumHeight(50)
        self.log_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)

        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.log_btn)
        main_layout.addWidget(control_group)

        # Haladás csoport
        progress_group = QGroupBox("📊 Haladás")
        progress_layout = QVBoxLayout(progress_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(30)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                text-align: center;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 6px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Kész az indításra...")
        self.status_label.setStyleSheet("font-size: 14px; color: #7f8c8d;")
        progress_layout.addWidget(self.status_label)

        main_layout.addWidget(progress_group)

        # Napló terület csoport
        log_group = QGroupBox("📝 Művelet napló")
        log_layout = QVBoxLayout(log_group)

        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(150)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #34495e;
                border-radius: 4px;
            }
        """)
        log_layout.addWidget(self.log_text)

        main_layout.addWidget(log_group)

        # Spacer hozzáadása
        spacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        main_layout.addItem(spacer)

        logging.info("LockMyPix Dekriptor alkalmazás elindítva")
        self.log_message("LockMyPix Dekriptor alkalmazás elindítva")

    def get_modern_style(self):
        """Modern stílus visszaadása"""
        return """
            QMainWindow {
                background-color: #ecf0f1;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #2c3e50;
                font-size: 14px;
            }
            QLineEdit {
                padding: 8px;
                border: 2px solid #bdc3c7;
                border-radius: 4px;
                font-size: 12px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
            QLabel {
                color: #2c3e50;
                font-size: 12px;
            }
        """

    def log_message(self, message):
        """Üzenet hozzáadása a naplóhoz"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.log_text.append(formatted_message)
        logging.info(message)

    def browse_input_folder(self):
        """Bemeneti mappa kiválasztása"""
        folder = QFileDialog.getExistingDirectory(self, "Válassza ki a bemeneti mappát")
        if folder:
            self.input_path_edit.setText(folder)
            # Automatikus kimeneti mappa beállítása
            unlocked_path = os.path.join(folder, "unlocked")
            self.output_path_edit.setText(unlocked_path)
            self.log_message(f"Bemeneti mappa kiválasztva: {folder}")

    def browse_output_folder(self):
        """Kimeneti mappa kiválasztása"""
        folder = QFileDialog.getExistingDirectory(self, "Válassza ki a kimeneti mappát")
        if folder:
            self.output_path_edit.setText(folder)
            self.log_message(f"Kimeneti mappa kiválasztva: {folder}")

    def get_password(self):
        """Jelszó bekérése"""
        from PyQt6.QtWidgets import QInputDialog
        password, ok = QInputDialog.getText(
            self, 
            "Jelszó szükséges", 
            "Adja meg a LockMyPix alkalmazás jelszavát:",
            QLineEdit.EchoMode.Password
        )
        if ok and password:
            return password
        return None

    def start_decryption(self):
        """Dekriptálás indítása"""
        input_dir = self.input_path_edit.text().strip()
        output_dir = self.output_path_edit.text().strip()

        # Validálás
        if not input_dir:
            QMessageBox.warning(self, "Hiányzó adat", "Kérem válasszon bemeneti mappát!")
            return

        if not output_dir:
            QMessageBox.warning(self, "Hiányzó adat", "Kérem válasszon kimeneti mappát!")
            return

        if not os.path.exists(input_dir):
            QMessageBox.critical(self, "Hiba", "A bemeneti mappa nem létezik!")
            return

        # Jelszó bekérése
        password = self.get_password()
        if not password:
            return

        # UI állapot változtatása
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        self.log_message("Dekriptálás indítása...")
        self.log_message(f"Bemeneti mappa: {input_dir}")
        self.log_message(f"Kimeneti mappa: {output_dir}")

        # Worker thread indítása
        self.worker = DecryptWorker(password, input_dir, output_dir)
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.status_updated.connect(self.update_status)
        self.worker.finished.connect(self.decryption_finished)
        self.worker.start()

    def stop_decryption(self):
        """Dekriptálás leállítása"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.log_message("Leállítás kérve...")

    def update_progress(self, value):
        """Haladás frissítése"""
        self.progress_bar.setValue(value)

    def update_status(self, message):
        """Állapot frissítése"""
        self.status_label.setText(message)
        self.log_message(message)

    def decryption_finished(self, success, message):
        """Dekriptálás befejezése"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if success:
            self.progress_bar.setValue(100)
            QMessageBox.information(self, "Siker", message)
            self.log_message(f"SIKER: {message}")
        else:
            QMessageBox.critical(self, "Hiba", message)
            self.log_message(f"HIBA: {message}")

        self.status_label.setText("Kész")

    def open_log(self):
        """Napló fájl megnyitása"""
        if self.log_file and os.path.exists(self.log_file):
            try:
                import subprocess
                import platform

                if platform.system() == "Windows":
                    os.startfile(self.log_file)
                elif platform.system() == "Darwin":  # macOS
                    subprocess.run(["open", self.log_file])
                else:  # Linux
                    subprocess.run(["xdg-open", self.log_file])

                self.log_message("Napló fájl megnyitva")
            except Exception as e:
                QMessageBox.warning(self, "Hiba", f"Nem sikerült megnyitni a napló fájlt: {str(e)}")
        else:
            QMessageBox.information(self, "Információ", "Nincs napló fájl vagy még nem létezik.")


def main():
    app = QApplication(sys.argv)

    # Alkalmazás ikonja (ha van)
    # app.setWindowIcon(QIcon("icon.png"))

    window = LockMyPixDecryptor()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
