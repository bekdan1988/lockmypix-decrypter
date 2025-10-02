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
    QLineEdit, QMessageBox, QGroupBox, QInputDialog, QComboBox
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont
from Crypto.Cipher import AES
from Crypto.Util import Counter

class LanguageManager:
    """Nyelvkezelő osztály"""
    def __init__(self):
        self.current_language = "hu"  # Alapértelmezett: magyar

        # Szöveg fordítások
        self.texts = {
            "hu": {
                # Főablak
                "window_title": "LockMyPix Decrypter",
                "app_title": "🔓 LockMyPix Decrypter",

                # Csoportok
                "folders_group": "📁 Mappák",
                "controls_group": "🎛️ Vezérlés",
                "progress_group": "📊 Haladás",
                "log_group": "📝 Napló",

                # Mezők
                "input_label": "Bemenet:",
                "output_label": "Kimenet:",
                "input_placeholder": "Titkosított fájlok mappája...",
                "output_placeholder": "Dekriptált fájlok helye...",

                # Gombok
                "browse_button": "Tallózás",
                "start_button": "▶️ Indítás",
                "stop_button": "⏹️ Leállítás",
                "log_button": "📋 Napló",

                # Állapotok
                "ready_status": "Kész az indításra",
                "finished_status": "Kész",

                # Üzenetek - Worker
                "password_test_error": "Jelszó teszt hiba",
                "no_files": "Nincsenek .6zu fájlok!",
                "interrupted": "Megszakítva",
                "processing": "Feldolgozás",
                "completed": "Kész",
                "error": "Hiba",
                "password_checking": "Jelszó ellenőrzése...",
                "wrong_password": "Helytelen jelszó!",
                "decrypting": "Dekriptálás...",
                "files_processed": "fájl sikeresen dekriptálva",

                # Üzenetek - UI
                "app_started": "Alkalmazás elindítva",
                "input_selected": "Bemenet",
                "output_selected": "Kimenet",
                "password_dialog_title": "Jelszó",
                "password_dialog_text": "LockMyPix jelszó:",
                "error_title": "Hiba",
                "missing_folders": "Adja meg a mappákat!",
                "folder_not_exists": "A bemeneti mappa nem létezik!",
                "decrypt_starting": "Dekriptálás indítása...",
                "stopping": "Leállítás...",
                "success_title": "Siker",
                "finished": "Befejezve",
                "log_opened": "Napló megnyitva",
                "info_title": "Info",
                "no_log_file": "Nincs napló fájl",
                "log_open_error": "Napló megnyitási hiba",

                # Dialógusok
                "input_folder_dialog": "Bemeneti mappa",
                "output_folder_dialog": "Kimeneti mappa",
            },
            "en": {
                # Main window
                "window_title": "LockMyPix Decrypter",
                "app_title": "🔓 LockMyPix Decrypter",

                # Groups
                "folders_group": "📁 Folders",
                "controls_group": "🎛️ Controls",
                "progress_group": "📊 Progress",
                "log_group": "📝 Log",

                # Fields
                "input_label": "Input:",
                "output_label": "Output:",
                "input_placeholder": "Encrypted files folder...",
                "output_placeholder": "Decrypted files location...",

                # Buttons
                "browse_button": "Browse",
                "start_button": "▶️ Start",
                "stop_button": "⏹️ Stop",
                "log_button": "📋 Log",

                # Status
                "ready_status": "Ready to start",
                "finished_status": "Finished",

                # Messages - Worker
                "password_test_error": "Password test error",
                "no_files": "No .6zu files found!",
                "interrupted": "Interrupted",
                "processing": "Processing",
                "completed": "Completed",
                "error": "Error",
                "password_checking": "Checking password...",
                "wrong_password": "Wrong password!",
                "decrypting": "Decrypting...",
                "files_processed": "files successfully decrypted",

                # Messages - UI
                "app_started": "Application started",
                "input_selected": "Input",
                "output_selected": "Output",
                "password_dialog_title": "Password",
                "password_dialog_text": "LockMyPix password:",
                "error_title": "Error",
                "missing_folders": "Please specify folders!",
                "folder_not_exists": "Input folder does not exist!",
                "decrypt_starting": "Starting decryption...",
                "stopping": "Stopping...",
                "success_title": "Success",
                "finished": "Finished",
                "log_opened": "Log file opened",
                "info_title": "Info",
                "no_log_file": "No log file",
                "log_open_error": "Log file open error",

                # Dialogs
                "input_folder_dialog": "Input Folder",
                "output_folder_dialog": "Output Folder",
            }
        }

    def set_language(self, lang_code):
        """Nyelv beállítása"""
        if lang_code in self.texts:
            self.current_language = lang_code

    def get_text(self, key):
        """Szöveg lekérdezése aktuális nyelven"""
        return self.texts[self.current_language].get(key, key)

class DecryptWorker(QThread):
    """Dekriptálási munkaszál"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, password, input_dir, output_dir, lang_manager):
        super().__init__()
        self.password = password
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.should_stop = False
        self.lang = lang_manager

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
            error_msg = f"{self.lang.get_text('password_test_error')}: {str(e)}"
            self.status_updated.emit(error_msg)
            return False

    def process_files(self):
        """Fájlok feldolgozása"""
        # Kimeneti könyvtár létrehozása
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        # .6zu fájlok keresése
        files = [f for f in os.listdir(self.input_dir) 
                if f.endswith('.6zu') and os.path.isfile(os.path.join(self.input_dir, f))]

        if not files:
            return False, self.lang.get_text("no_files")

        successful_count = 0

        for i, filename in enumerate(files):
            if self.should_stop:
                return False, self.lang.get_text("interrupted")

            try:
                input_path = os.path.join(self.input_dir, filename)
                status_msg = f"{self.lang.get_text('processing')}: {filename}"
                self.status_updated.emit(status_msg)

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
                completed_msg = f"{self.lang.get_text('completed')}: {output_filename}"
                self.status_updated.emit(completed_msg)

            except Exception as e:
                error_msg = f"{self.lang.get_text('error')} {filename}: {str(e)}"
                self.status_updated.emit(error_msg)

            # Haladás frissítése
            progress = int((i + 1) / len(files) * 100)
            self.progress_updated.emit(progress)

        result_msg = f"{successful_count}/{len(files)} {self.lang.get_text('files_processed')}"
        return True, result_msg

    def stop(self):
        """Műveletek leállítása"""
        self.should_stop = True

    def run(self):
        """Fő futási logika"""
        try:
            # Jelszó ellenőrzés
            self.status_updated.emit(self.lang.get_text("password_checking"))
            if not self.test_password():
                self.finished.emit(False, self.lang.get_text("wrong_password"))
                return

            # Fájlok feldolgozása
            self.status_updated.emit(self.lang.get_text("decrypting"))
            success, message = self.process_files()
            self.finished.emit(success, message)

        except Exception as e:
            error_msg = f"{self.lang.get_text('error')}: {str(e)}"
            self.finished.emit(False, error_msg)

class LockMyPixDecrypter(QMainWindow):
    """Fő alkalmazás ablak"""

    def __init__(self):
        super().__init__()
        self.worker = None
        self.lang = LanguageManager()
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
        self.setWindowTitle(self.lang.get_text("window_title"))
        self.setGeometry(300, 300, 750, 550)
        self.setStyleSheet(self.get_style())

        # Központi widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Fejléc sor - Cím és nyelvválasztó
        header_layout = QHBoxLayout()

        # Cím
        self.title = QLabel(self.lang.get_text("app_title"))
        self.title.setObjectName("appTitle")
        header_layout.addWidget(self.title)

        # Spacer a középen
        header_layout.addStretch()

        # Nyelvválasztó a jobb oldalon
        self.language_combo = QComboBox()
        self.language_combo.addItem("Magyar", "hu")
        self.language_combo.addItem("English", "en")
        self.language_combo.currentIndexChanged.connect(self.language_changed)
        self.language_combo.setMaximumWidth(90)
        self.language_combo.setStyleSheet("""
            QComboBox {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #5a7ebf,
                    stop: 0.5 #4a6ea9,
                    stop: 1 #3a5e99
                );
                color: #ffffff;
                border: 2px solid #2a4e89;
                border-radius: 8px;
                padding: 8px 32px 8px 12px; /* extra right padding for arrow */
                font-size: 14px;
                font-weight: bold;
                min-height: 20px;
                min-width: 90px;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 24px;
                border-left: 1px solid #3a5e99;
            }
            QComboBox::down-arrow {
                image: none; /* hide default */
                width: 0;
                height: 0;
                border-left: 6px solid transparent;
                border-right: 6px solid transparent;
                border-top: 8px solid #ffffff;
            }
            QComboBox QAbstractItemView {
                background-color: #4a4a4a;
                color: #ffffff;
                border: 1px solid #555555;
                selection-background-color: #0078d4;
                padding: 4px;
            }
        """)
        
        header_layout.addWidget(self.language_combo)

        main_layout.addLayout(header_layout)

        # Fájl beállítások
        self.file_group = self.create_file_group()
        main_layout.addWidget(self.file_group)

        # Vezérlők
        self.control_group = self.create_control_group()
        main_layout.addWidget(self.control_group)

        # Haladás
        self.progress_group = self.create_progress_group()
        main_layout.addWidget(self.progress_group)

        # Napló
        self.log_group = self.create_log_group()
        main_layout.addWidget(self.log_group)

        self.log_message(self.lang.get_text("app_started"))

    def create_file_group(self):
        """Fájl beállítások csoport"""
        group = QGroupBox(self.lang.get_text("folders_group"))
        layout = QVBoxLayout(group)

        # Bemenet
        input_layout = QHBoxLayout()
        self.input_label = QLabel(self.lang.get_text("input_label"))
        input_layout.addWidget(self.input_label)

        self.input_path = QLineEdit()
        self.input_path.setPlaceholderText(self.lang.get_text("input_placeholder"))

        self.input_browse = QPushButton(self.lang.get_text("browse_button"))
        self.input_browse.clicked.connect(self.browse_input)
        self.input_browse.setStyleSheet(self.get_browse_button_style())

        input_layout.addWidget(self.input_path)
        input_layout.addWidget(self.input_browse)
        layout.addLayout(input_layout)

        # Kimenet
        output_layout = QHBoxLayout()
        self.output_label = QLabel(self.lang.get_text("output_label"))
        output_layout.addWidget(self.output_label)

        self.output_path = QLineEdit()
        self.output_path.setPlaceholderText(self.lang.get_text("output_placeholder"))

        self.output_browse = QPushButton(self.lang.get_text("browse_button"))
        self.output_browse.clicked.connect(self.browse_output)
        self.output_browse.setStyleSheet(self.get_browse_button_style())

        output_layout.addWidget(self.output_path)
        output_layout.addWidget(self.output_browse)
        layout.addLayout(output_layout)

        return group

    def create_control_group(self):
        """Vezérlő gombok csoport"""
        group = QGroupBox(self.lang.get_text("controls_group"))
        layout = QHBoxLayout(group)

        self.start_btn = QPushButton(self.lang.get_text("start_button"))
        self.start_btn.clicked.connect(self.start_decrypt)
        self.start_btn.setStyleSheet(self.get_control_button_style("#27ae60"))

        self.stop_btn = QPushButton(self.lang.get_text("stop_button"))
        self.stop_btn.clicked.connect(self.stop_decrypt)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(self.get_control_button_style("#e74c3c"))

        self.log_btn = QPushButton(self.lang.get_text("log_button"))
        self.log_btn.clicked.connect(self.open_log)
        self.log_btn.setStyleSheet(self.get_control_button_style("#3498db"))

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.log_btn)

        return group

    def create_progress_group(self):
        """Haladás csoport"""
        group = QGroupBox(self.lang.get_text("progress_group"))
        layout = QVBoxLayout(group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(30)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel(self.lang.get_text("ready_status"))
        self.status_label.setStyleSheet("color: #cccccc; font-size: 13px;")
        layout.addWidget(self.status_label)

        return group

    def create_log_group(self):
        """Napló csoport"""
        group = QGroupBox(self.lang.get_text("log_group"))
        layout = QVBoxLayout(group)

        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(120)
        layout.addWidget(self.log_text)

        return group

    def get_browse_button_style(self):
        """Tallózás gombok stílusa"""
        return """
            QPushButton {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #5a7ebf,
                    stop: 0.5 #4a6ea9,
                    stop: 1 #3a5e99
                );
                color: white;
                border: 2px solid #2a4e89;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 13px;
                min-width: 100px;
                min-height: 40px;
                text-align: center;
            }
            QPushButton:hover {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #6a8ecf,
                    stop: 0.5 #5a7eb9,
                    stop: 1 #4a6ea9
                );
                border: 2px solid #3a5e99;
            }
            QPushButton:pressed {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #3a5e99,
                    stop: 0.5 #2a4e89,
                    stop: 1 #1a3e79
                );
                border: 2px solid #1a3e79;
                padding-top: 12px;
                padding-bottom: 8px;
            }
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #777777;
                border: 2px solid #444444;
            }
        """

    def get_control_button_style(self, color):
        """Vezérlő gombok stílusa"""
        hover_color = self.get_lighter_color(color)
        pressed_color = self.get_darker_color(color)

        return f"""
            QPushButton {{
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 {color},
                    stop: 0.5 {self.get_darker_color(color, 0.1)},
                    stop: 1 {self.get_darker_color(color, 0.2)}
                );
                color: white;
                border: 2px solid {self.get_darker_color(color, 0.3)};
                border-radius: 8px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 14px;
                min-width: 120px;
                min-height: 45px;
                text-align: center;
            }}
            QPushButton:hover {{
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 {hover_color},
                    stop: 0.5 {color},
                    stop: 1 {self.get_darker_color(color, 0.1)}
                );
                border: 2px solid {self.get_darker_color(color, 0.2)};
            }}
            QPushButton:pressed {{
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 {pressed_color},
                    stop: 0.5 {self.get_darker_color(color, 0.3)},
                    stop: 1 {self.get_darker_color(color, 0.4)}
                );
                border: 2px solid {self.get_darker_color(color, 0.4)};
                padding-top: 14px;
                padding-bottom: 10px;
            }}
            QPushButton:disabled {{
                background-color: #2a2a2a;
                color: #777777;
                border: 2px solid #444444;
            }}
        """

    def get_lighter_color(self, color, amount=0.2):
        """Világosabb szín generálása"""
        if color.startswith("#"):
            color = color[1:]
        r = int(color[0:2], 16)
        g = int(color[2:4], 16)
        b = int(color[4:6], 16)

        r = min(255, int(r + (255 - r) * amount))
        g = min(255, int(g + (255 - g) * amount))
        b = min(255, int(b + (255 - b) * amount))

        return f"#{r:02x}{g:02x}{b:02x}"

    def get_darker_color(self, color, amount=0.2):
        """Sötétebb szín generálása"""
        if color.startswith("#"):
            color = color[1:]
        r = int(color[0:2], 16)
        g = int(color[2:4], 16)
        b = int(color[4:6], 16)

        r = max(0, int(r * (1 - amount)))
        g = max(0, int(g * (1 - amount)))
        b = max(0, int(b * (1 - amount)))

        return f"#{r:02x}{g:02x}{b:02x}"

    def language_changed(self):
        """Nyelv változás kezelése"""
        lang_code = self.language_combo.currentData()
        self.lang.set_language(lang_code)
        self.update_ui_texts()

    def update_ui_texts(self):
        """UI szövegek frissítése"""
        # Főablak
        self.setWindowTitle(self.lang.get_text("window_title"))
        self.title.setText(self.lang.get_text("app_title"))

        # Csoportok
        self.file_group.setTitle(self.lang.get_text("folders_group"))
        self.control_group.setTitle(self.lang.get_text("controls_group"))
        self.progress_group.setTitle(self.lang.get_text("progress_group"))
        self.log_group.setTitle(self.lang.get_text("log_group"))

        # Mezők
        self.input_label.setText(self.lang.get_text("input_label"))
        self.output_label.setText(self.lang.get_text("output_label"))
        self.input_path.setPlaceholderText(self.lang.get_text("input_placeholder"))
        self.output_path.setPlaceholderText(self.lang.get_text("output_placeholder"))

        # Gombok
        self.input_browse.setText(self.lang.get_text("browse_button"))
        self.output_browse.setText(self.lang.get_text("browse_button"))
        self.start_btn.setText(self.lang.get_text("start_button"))
        self.stop_btn.setText(self.lang.get_text("stop_button"))
        self.log_btn.setText(self.lang.get_text("log_button"))

        # Állapot
        if self.status_label.text() in [self.lang.texts["hu"]["ready_status"], self.lang.texts["en"]["ready_status"]]:
            self.status_label.setText(self.lang.get_text("ready_status"))
        elif self.status_label.text() in [self.lang.texts["hu"]["finished_status"], self.lang.texts["en"]["finished_status"]]:
            self.status_label.setText(self.lang.get_text("finished_status"))

    def get_style(self):
        """
            QLabel#appTitle {
                color: #ffffff;
                font-size: 28px;
                font-weight: bold;
                margin-bottom: 15px;
            }
Sötét téma CSS"""
        return """
            QMainWindow { 
                background-color: #2b2b2b; 
            }

            QGroupBox {
                font-weight: bold;
                font-size: 14px;
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
                font-size: 20px;
            }

            QLineEdit {
                padding: 8px;
                border: 2px solid #555555;
                border-radius: 6px;
                background-color: #4a4a4a;
                color: #ffffff;
                font-size: 13px;
                min-height: 35px;
            }

            QLineEdit:focus { 
                border-color: #0078d4; 
            }

            QLabel { 
                color: #ffffff; 
                font-size: 13px;
                font-weight: bold;
            }

            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #555555;
                border-radius: 4px;
            }

            QProgressBar {
                border: 2px solid #555555;
                border-radius: 8px;
                text-align: center;
                color: #ffffff;
                background-color: #3c3c3c;
                font-size: 13px;
                font-weight: bold;
                min-height: 30px;
            }

            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 6px;
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
        folder = QFileDialog.getExistingDirectory(self, self.lang.get_text("input_folder_dialog"))
        if folder:
            self.input_path.setText(folder)
            # Automatikus kimeneti mappa
            self.output_path.setText(os.path.join(folder, "decrypted"))
            log_msg = f"{self.lang.get_text('input_selected')}: {folder}"
            self.log_message(log_msg)

    def browse_output(self):
        """Kimeneti mappa kiválasztás"""
        folder = QFileDialog.getExistingDirectory(self, self.lang.get_text("output_folder_dialog"))
        if folder:
            self.output_path.setText(folder)
            log_msg = f"{self.lang.get_text('output_selected')}: {folder}"
            self.log_message(log_msg)

    def get_password(self):
        """Jelszó bekérés"""
        password, ok = QInputDialog.getText(
            self, self.lang.get_text("password_dialog_title"),
            self.lang.get_text("password_dialog_text"),
            QLineEdit.EchoMode.Password
        )
        return password if ok and password else None

    def start_decrypt(self):
        """Dekriptálás indítása"""
        input_dir = self.input_path.text().strip()
        output_dir = self.output_path.text().strip()

        # Validálás
        if not input_dir or not output_dir:
            QMessageBox.warning(self, self.lang.get_text("error_title"),
                              self.lang.get_text("missing_folders"))
            return

        if not os.path.exists(input_dir):
            QMessageBox.critical(self, self.lang.get_text("error_title"),
                               self.lang.get_text("folder_not_exists"))
            return

        # Jelszó bekérés
        password = self.get_password()
        if not password:
            return

        # UI állapot
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.log_message(self.lang.get_text("decrypt_starting"))

        # Worker indítása
        self.worker = DecryptWorker(password, input_dir, output_dir, self.lang)
        self.worker.progress_updated.connect(self.progress_bar.setValue)
        self.worker.status_updated.connect(self.update_status)
        self.worker.finished.connect(self.decrypt_finished)
        self.worker.start()

    def stop_decrypt(self):
        """Dekriptálás leállítása"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.log_message(self.lang.get_text("stopping"))

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
            QMessageBox.information(self, self.lang.get_text("success_title"), message)
        else:
            QMessageBox.critical(self, self.lang.get_text("error_title"), message)

        self.status_label.setText(self.lang.get_text("finished_status"))
        finished_msg = f"{self.lang.get_text('finished')}: {message}"
        self.log_message(finished_msg)

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
                self.log_message(self.lang.get_text("log_opened"))
            else:
                QMessageBox.information(self, self.lang.get_text("info_title"),
                                      self.lang.get_text("no_log_file"))
        except Exception as e:
            error_msg = f"{self.lang.get_text('log_open_error')}: {e}"
            QMessageBox.warning(self, self.lang.get_text("error_title"), error_msg)

def main():
    """Főprogram"""
    app = QApplication(sys.argv)
    window = LockMyPixDecrypter()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
