#!/usr/bin/env python3

import sys
import os
import hashlib
import binascii
from pathlib import Path
from datetime import datetime
import logging

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QTextEdit, QProgressBar,
    QLineEdit, QMessageBox, QGroupBox, QInputDialog
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont

from Crypto.Cipher import AES
from Crypto.Util import Counter


class DecryptWorker(QThread):
    """Dekriptálási munkaszál"""

    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, password, input_dir, output_dir):
        super().__init__()
        self.password = password
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.should_stop = False

        # Fájlkiterjesztés konverzió
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

    def create_cipher(self):
        """AES cipher létrehozása"""
        key = hashlib.sha1(self.password.encode()).digest()[:16]
        iv = key
        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        return AES.new(key, AES.MODE_CTR, counter=counter)

    def test_password(self):
        """Jelszó validálása"""
        try:
            for filename in os.listdir(self.input_dir):
                if filename.endswith(".6zu"):
                    file_path = os.path.join(self.input_dir, filename)
                    cipher = self.create_cipher()

                    with open(file_path, "rb") as f:
                        encrypted_data = f.read(16)

                    decrypted_data = cipher.decrypt(encrypted_data)
                    header = binascii.hexlify(decrypted_data).decode("utf8")

                    return header.startswith("ffd8ff")  # JPEG header
            return False
        except Exception as e:
            self.status_updated.emit(f"Jelszó teszt hiba: {str(e)}")
            return False

    def process_files(self):
        """Fájlok feldolgozása"""
        # Kimeneti könyvtár létrehozása
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        # .6zu fájlok keresése
        files = [f for f in os.listdir(self.input_dir) 
                if f.endswith('.6zu') and os.path.isfile(os.path.join(self.input_dir, f))]

        if not files:
            return False, "Nincsenek .6zu fájlok!"

        successful_count = 0

        for i, filename in enumerate(files):
            if self.should_stop:
                return False, "Megszakítva"

            try:
                input_path = os.path.join(self.input_dir, filename)
                self.status_updated.emit(f"Feldolgozás: {filename}")

                # Dekriptálás
                cipher = self.create_cipher()
                with open(input_path, "rb") as f:
                    decrypted_data = cipher.decrypt(f.read())

                # Kimeneti fájlnév meghatározása
                basename, ext = os.path.splitext(filename)
                new_ext = self.extension_map.get(ext, ".unknown")
                output_filename = basename + new_ext
                output_path = os.path.join(self.output_dir, output_filename)

                # Mentés
                with open(output_path, "wb") as f:
                    f.write(decrypted_data)

                successful_count += 1
                self.status_updated.emit(f"Kész: {output_filename}")

            except Exception as e:
                self.status_updated.emit(f"Hiba {filename}: {str(e)}")

            # Haladás frissítése
            progress = int((i + 1) / len(files) * 100)
            self.progress_updated.emit(progress)

        return True, f"{successful_count}/{len(files)} fájl sikeresen dekriptálva"

    def stop(self):
        """Műveletek leállítása"""
        self.should_stop = True

    def run(self):
        """Fő futási logika"""
        try:
            # Jelszó ellenőrzés
            self.status_updated.emit("Jelszó ellenőrzése...")
            if not self.test_password():
                self.finished.emit(False, "Helytelen jelszó!")
                return

            # Fájlok feldolgozása
            self.status_updated.emit("Dekriptálás...")
            success, message = self.process_files()
            self.finished.emit(success, message)

        except Exception as e:
            self.finished.emit(False, f"Hiba: {str(e)}")


class LockMyPixDecryptor(QMainWindow):
    """Fő alkalmazás ablak"""

    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_logging()
        self.init_ui()

    def setup_logging(self):
        """Naplózás beállítása"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"decrypt_{timestamp}.log"

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

    def init_ui(self):
        """UI inicializálása"""
        self.setWindowTitle("LockMyPix Decrypter")
        self.setGeometry(300, 300, 700, 500)
        self.setStyleSheet(self.get_style())

        # Központi widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Cím
        title = QLabel("🔓 LockMyPix Decrypter")
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ffffff; margin-bottom: 15px;")
        main_layout.addWidget(title)

        # Fájl beállítások
        file_group = self.create_file_group()
        main_layout.addWidget(file_group)

        # Vezérlők
        control_group = self.create_control_group()
        main_layout.addWidget(control_group)

        # Haladás
        progress_group = self.create_progress_group()
        main_layout.addWidget(progress_group)

        # Napló
        log_group = self.create_log_group()
        main_layout.addWidget(log_group)

        self.log_message("Alkalmazás elindítva")

    def create_file_group(self):
        """Fájl beállítások csoport"""
        group = QGroupBox("📁 Mappák")
        layout = QVBoxLayout(group)

        # Bemenet
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Bemenet:"))
        self.input_path = QLineEdit()
        self.input_path.setPlaceholderText("Titkosított fájlok mappája...")
        input_browse = QPushButton("Tallózás")
        input_browse.clicked.connect(self.browse_input)
        input_layout.addWidget(self.input_path)
        input_layout.addWidget(input_browse)
        layout.addLayout(input_layout)

        # Kimenet
        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("Kimenet:"))
        self.output_path = QLineEdit()
        self.output_path.setPlaceholderText("Dekriptált fájlok helye...")
        output_browse = QPushButton("Tallózás")
        output_browse.clicked.connect(self.browse_output)
        output_layout.addWidget(self.output_path)
        output_layout.addWidget(output_browse)
        layout.addLayout(output_layout)

        return group

    def create_control_group(self):
        """Vezérlő gombok csoport"""
        group = QGroupBox("🎛️ Vezérlés")
        layout = QHBoxLayout(group)

        self.start_btn = QPushButton("▶️ Indítás")
        self.start_btn.clicked.connect(self.start_decrypt)
        self.start_btn.setStyleSheet("QPushButton { background-color: #27ae60; }")

        self.stop_btn = QPushButton("⏹️ Leállítás")
        self.stop_btn.clicked.connect(self.stop_decrypt)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #e74c3c; }")

        self.log_btn = QPushButton("📋 Napló")
        self.log_btn.clicked.connect(self.open_log)
        self.log_btn.setStyleSheet("QPushButton { background-color: #3498db; }")

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.log_btn)

        return group

    def create_progress_group(self):
        """Haladás csoport"""
        group = QGroupBox("📊 Haladás")
        layout = QVBoxLayout(group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(25)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Kész az indításra")
        self.status_label.setStyleSheet("color: #cccccc;")
        layout.addWidget(self.status_label)

        return group

    def create_log_group(self):
        """Napló csoport"""
        group = QGroupBox("📝 Napló")
        layout = QVBoxLayout(group)

        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(120)
        layout.addWidget(self.log_text)

        return group

    def get_style(self):
        """Sötét téma CSS"""
        return """
        QMainWindow { background-color: #2b2b2b; }
        QGroupBox {
            font-weight: bold;
            border: 2px solid #555555;
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
            background-color: #3c3c3c;
            color: #ffffff;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
            color: #ffffff;
        }
        QLineEdit {
            padding: 6px;
            border: 2px solid #555555;
            border-radius: 4px;
            background-color: #4a4a4a;
            color: #ffffff;
        }
        QLineEdit:focus { border-color: #0078d4; }
        QPushButton {
            background-color: #404040;
            color: white;
            border: 1px solid #555555;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 80px;
            min-height: 30px;
        }
        QPushButton:hover { background-color: #505050; }
        QPushButton:disabled { background-color: #2a2a2a; color: #777777; }
        QLabel { color: #ffffff; }
        QTextEdit {
            background-color: #1e1e1e;
            color: #ffffff;
            font-family: 'Courier New', monospace;
            border: 1px solid #555555;
            border-radius: 4px;
        }
        QProgressBar {
            border: 2px solid #555555;
            border-radius: 6px;
            text-align: center;
            color: #ffffff;
            background-color: #3c3c3c;
        }
        QProgressBar::chunk {
            background-color: #0078d4;
            border-radius: 4px;
        }
        """

    def log_message(self, message):
        """Napló üzenet"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        self.log_text.append(formatted)
        logging.info(message)

    def browse_input(self):
        """Bemeneti mappa kiválasztás"""
        folder = QFileDialog.getExistingDirectory(self, "Bemeneti mappa")
        if folder:
            self.input_path.setText(folder)
            # Automatikus kimeneti mappa
            self.output_path.setText(os.path.join(folder, "decrypted"))
            self.log_message(f"Bemenet: {folder}")

    def browse_output(self):
        """Kimeneti mappa kiválasztás"""
        folder = QFileDialog.getExistingDirectory(self, "Kimeneti mappa")
        if folder:
            self.output_path.setText(folder)
            self.log_message(f"Kimenet: {folder}")

    def get_password(self):
        """Jelszó bekérés"""
        password, ok = QInputDialog.getText(
            self, "Jelszó", "LockMyPix jelszó:",
            QLineEdit.EchoMode.Password
        )
        return password if ok and password else None

    def start_decrypt(self):
        """Dekriptálás indítása"""
        input_dir = self.input_path.text().strip()
        output_dir = self.output_path.text().strip()

        # Validálás
        if not input_dir or not output_dir:
            QMessageBox.warning(self, "Hiba", "Adja meg a mappákat!")
            return

        if not os.path.exists(input_dir):
            QMessageBox.critical(self, "Hiba", "A bemeneti mappa nem létezik!")
            return

        # Jelszó bekérés
        password = self.get_password()
        if not password:
            return

        # UI állapot
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.log_message("Dekriptálás indítása...")

        # Worker indítása
        self.worker = DecryptWorker(password, input_dir, output_dir)
        self.worker.progress_updated.connect(self.progress_bar.setValue)
        self.worker.status_updated.connect(self.update_status)
        self.worker.finished.connect(self.decrypt_finished)
        self.worker.start()

    def stop_decrypt(self):
        """Dekriptálás leállítása"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.log_message("Leállítás...")

    def update_status(self, message):
        """Állapot frissítés"""
        self.status_label.setText(message)
        self.log_message(message)

    def decrypt_finished(self, success, message):
        """Dekriptálás befejezés"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if success:
            self.progress_bar.setValue(100)
            QMessageBox.information(self, "Siker", message)
        else:
            QMessageBox.critical(self, "Hiba", message)

        self.status_label.setText("Kész")
        self.log_message(f"Befejezve: {message}")

    def open_log(self):
        """Napló megnyitása"""
        try:
            if self.log_file.exists():
                import subprocess, platform
                system = platform.system()
                if system == "Windows":
                    os.startfile(str(self.log_file))
                elif system == "Darwin":
                    subprocess.run(["open", str(self.log_file)])
                else:
                    subprocess.run(["xdg-open", str(self.log_file)])
                self.log_message("Napló megnyitva")
            else:
                QMessageBox.information(self, "Info", "Nincs napló fájl")
        except Exception as e:
            QMessageBox.warning(self, "Hiba", f"Napló megnyitási hiba: {e}")


def main():
    """Főprogram"""
    app = QApplication(sys.argv)
    window = LockMyPixDecryptor()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
