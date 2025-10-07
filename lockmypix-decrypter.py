#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import hashlib
import binascii
import zipfile
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime
import logging

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QTextEdit, QProgressBar,
    QLineEdit, QMessageBox, QGroupBox, QInputDialog, QComboBox
)

from PyQt6 import QtGui
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont, QIcon
from Crypto.Cipher import AES
from Crypto.Util import Counter

# EXIF támogatás (opcionális)
try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ======================================
# SEGÉDFÜGGVÉNYEK - Intelligens név- és dátumkezelés
# ======================================

def set_file_timestamps(file_path, datetime_obj):
    """Fájl időbélyegek beállítása"""
    timestamp = datetime_obj.timestamp()
    os.utime(file_path, (timestamp, timestamp))  # (access_time, modified_time)

def is_image_file(file_path):
    """Ellenőrzi hogy képfájl-e"""
    image_extensions = {'.jpg', '.jpeg', '.png', '.heic', '.heif', '.tiff', '.bmp', '.gif', '.webp'}
    return Path(file_path).suffix.lower() in image_extensions

def is_video_file(file_path):
    """Ellenőrzi hogy videófájl-e"""
    video_extensions = {'.mp4', '.mov', '.avi', '.mkv', '.wmv', '.flv', '.webm', '.m4v'}
    return Path(file_path).suffix.lower() in video_extensions

def get_exif_datetime(image_path):
    """EXIF DateTime kinyerése képfájlból"""
    if not HAS_PIL:
        return None

    try:
        with Image.open(image_path) as img:
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    if tag == "DateTime":
                        return datetime.strptime(value, "%Y:%m:%d %H:%M:%S")
    except:
        pass
    return None

def detect_extension_by_header(file_path):
    """Fájl tartalom alapján kiterjesztés meghatározás"""
    default_ext = Path(file_path).suffix or '.bin'
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)

        # JPEG
        if header.startswith(b'\xff\xd8\xff'):
            return '.jpg'
        # PNG  
        elif header.startswith(b'\x89PNG'):
            return '.png'
        # MP4
        elif b'ftyp' in header:
            return '.mp4'
        # GIF
        elif header.startswith(b'GIF8'):
            return '.gif'
        # BMP
        elif header.startswith(b'BM'):
            return '.bmp'

    except:
        pass

    return default_ext

def generate_intelligent_filename(file_mapping, hash_id, decrypted_path, sort_order):
    """
    Intelligens fájlnév generálás hibrid módszerrel

    Args:
        file_mapping (dict): Sort.db mapping adatok
        hash_id (str): Fájl hash azonosító
        decrypted_path (str): Dekriptált fájl útvonala
        sort_order (int): Rendezési sorszám

    Returns:
        str: Generált fájlnév
    """

    # 1. IMGPATH tábla ellenőrzés (ha implementált)
    if file_mapping and hash_id in file_mapping and 'original_path' in file_mapping[hash_id]:
        original_path = file_mapping[hash_id]['original_path']
        if original_path:
            return os.path.basename(original_path)

    # 2. EXIF alapú névgenerálás (képfájlokhoz)
    if is_image_file(decrypted_path):
        exif_date = get_exif_datetime(decrypted_path)
        if exif_date:
            date_str = exif_date.strftime("%Y%m%d_%H%M%S")
            file_ext = Path(decrypted_path).suffix
            return f"IMG_{date_str}{file_ext}"

    # 3. Videó fájlok header alapú névgenerálás (egyszerűsített)
    if is_video_file(decrypted_path):
        try:
            # Fájl létrehozási ideje alapján
            ctime = os.path.getctime(decrypted_path)
            creation_date = datetime.fromtimestamp(ctime)
            date_str = creation_date.strftime("%Y%m%d_%H%M%S")
            file_ext = Path(decrypted_path).suffix
            return f"VID_{date_str}{file_ext}"
        except:
            pass

    # 4. Sorrend alapú fallback
    file_ext = detect_extension_by_header(decrypted_path)
    return f"file_{sort_order:03d}{file_ext}"

def restore_file_timestamps(encrypted_path, decrypted_path, file_mapping=None, filename_key=None):
    """
    Fájldátumok helyreállítása prioritás alapján

    Args:
        encrypted_path (str): Eredeti titkosított fájl útvonala
        decrypted_path (str): Dekriptált fájl útvonala  
        file_mapping (dict): Sort.db mapping adatok (opcionális)
        filename_key (str): Fájl azonosító a mapping-ben (opcionális)
    """

    # 1. ELSŐDLEGES: Sort.db adatbázis dátum
    if file_mapping and filename_key and filename_key in file_mapping:
        mapping_info = file_mapping[filename_key]
        if 'date_modified' in mapping_info:
            try:
                original_date = datetime.fromisoformat(mapping_info['date_modified'])
                set_file_timestamps(decrypted_path, original_date)
                return
            except:
                pass

    # 2. MÁSODLAGOS: EXIF adatok (csak képfájlokhoz)
    if HAS_PIL and is_image_file(decrypted_path):
        exif_date = get_exif_datetime(decrypted_path)
        if exif_date:
            set_file_timestamps(decrypted_path, exif_date)
            return

    # 3. HARMADLAGOS: OS fájl metadatok másolása
    if os.path.exists(encrypted_path):
        try:
            shutil.copystat(encrypted_path, decrypted_path)
            return
        except:
            pass

    # 4. NEGYEDLEGES: Aktuális idő (fallback)
    current_time = datetime.now()
    set_file_timestamps(decrypted_path, current_time)

def rename_folder_by_timestamps(folder_path):
    """
    Mappa átnevezése a benne lévő fájlok legkorábbi és legkésőbbi dátuma alapján
    """
    if not os.path.exists(folder_path):
        return folder_path

    timestamps = []
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                ctime = os.path.getctime(file_path)
                timestamps.append(ctime)
            except:
                continue

    if not timestamps:
        return folder_path  # Nincs fájl a mappában

    # Legkorábbi és legkésőbbi timestamp
    earliest = datetime.fromtimestamp(min(timestamps)).strftime("%Y%m%d")
    latest = datetime.fromtimestamp(max(timestamps)).strftime("%Y%m%d")

    # Új mappanév
    parent = os.path.dirname(folder_path)
    if earliest == latest:
        new_name = earliest
    else:
        new_name = f"{earliest}-{latest}"
    new_path = os.path.join(parent, new_name)

    # Ütközés kezelése
    suffix = 1
    temp_path = new_path
    while os.path.exists(temp_path) and temp_path != folder_path:
        temp_path = f"{new_path}_{suffix}"
        suffix += 1
    new_path = temp_path

    # Átnevezés
    if new_path != folder_path:
        try:
            os.rename(folder_path, new_path)
            print(f"📂 Mappa átnevezve: {os.path.basename(folder_path)} → {os.path.basename(new_path)}")
            return new_path
        except Exception as e:
            print(f"⚠️ Mappa átnevezési hiba: {e}")

    return folder_path

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
                "input_placeholder": "Titkosított fájlok vagy .zip.cmpexport...",
                "output_placeholder": "Dekriptált fájlok helye...",

                # Gombok
                "browse_button": "Tallózás",
                "start_button": "▶️ Indítás",
                "stop_button": "⏹️ Leállítás",
                "log_button": "📋 Napló",

                # Állapotok
                "ready_status": "Kész - Backup és egyedi fájlok támogatva",
                "finished_status": "Kész",

                # Üzenetek - Worker
                "password_test_error": "Jelszó teszt hiba",
                "no_files": "Nincsenek támogatott titkosított fájlok!",
                "interrupted": "Megszakítva",
                "processing": "Feldolgozás",
                "completed": "Kész",
                "error": "Hiba",
                "password_checking": "Jelszó ellenőrzése...",
                "wrong_password": "Helytelen jelszó!",
                "decrypting": "Dekriptálás...",
                "files_processed": "fájl sikeresen dekriptálva",

                # .zip.cmpexport üzenetek
                "cmpexport_detected": "LockMyPix backup észlelve",
                "extracting_zip": "ZIP kicsomagolása",
                "analyzing_sortdb": "Sort.db elemzése",
                "loading_keyfiles": "Kulcs fájlok betöltése",
                "decrypting_folder": "Titkosított mappa dekriptálása",
                "mapping_files": "Fájlnév mapping alkalmazása",
                "cleanup_temp": "Temp fájlok törlése",
                "backup_processed": "backup sikeresen feldolgozva",
                "intelligent_naming": "Intelligens névgenerálás",
                "timestamp_restore": "Időbélyegek helyreállítása",
                "folder_rename": "Mappák átnevezése",

                # Üzenetek - UI
                "app_started": "Alkalmazás elindítva",
                "input_selected": "Bemenet",
                "output_selected": "Kimenet",
                "password_prompt": "Add meg a jelszót:",
                "password_title": "Jelszó szükséges",
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
                "input_folder_dialog": "Bemeneti mappa vagy fájl",
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
                "input_placeholder": "Encrypted files or .zip.cmpexport...",
                "output_placeholder": "Decrypted files location...",

                # Buttons
                "browse_button": "Browse",
                "start_button": "▶️ Start",
                "stop_button": "⏹️ Stop",
                "log_button": "📋 Log",

                # Status
                "ready_status": "Ready - Backup and individual files supported",
                "finished_status": "Finished",

                # Messages - Worker
                "password_test_error": "Password test error",
                "no_files": "No supported encrypted files found!",
                "interrupted": "Interrupted",
                "processing": "Processing",
                "completed": "Completed",
                "error": "Error",
                "password_checking": "Checking password...",
                "wrong_password": "Wrong password!",
                "decrypting": "Decrypting...",
                "files_processed": "files successfully decrypted",

                # .zip.cmpexport messages
                "cmpexport_detected": "LockMyPix backup detected",
                "extracting_zip": "Extracting ZIP",
                "analyzing_sortdb": "Analyzing sort.db",
                "loading_keyfiles": "Loading key files",
                "decrypting_folder": "Decrypting encrypted folder",
                "mapping_files": "Applying filename mapping",
                "cleanup_temp": "Cleaning temp files",
                "backup_processed": "backup successfully processed",
                "intelligent_naming": "Intelligent name generation",
                "timestamp_restore": "Timestamp restoration",
                "folder_rename": "Folder renaming",

                # Messages - UI
                "app_started": "Application started",
                "input_selected": "Input",
                "output_selected": "Output",
                "password_prompt": "Enter password:",
                "password_title": "Password Required",
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
                "input_folder_dialog": "Input Folder or File",
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
    """Dekriptálási munkaszál - KIBŐVÍTVE intelligens név- és dátumkezeléssel"""
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

        # Fájlkiterjesztés konverzió (KIBŐVÍTVE)
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

            # ÚJ: Backup támogatás
            ".zip.cmpexport": ".backup"
        }

    def create_cipher(self):
        """AES cipher létrehozása (EREDETI ALGORITMUS)"""
        key = hashlib.sha1(self.password.encode()).digest()[:16]
        iv = key
        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        return AES.new(key, AES.MODE_CTR, counter=counter)

    def test_password(self):
        """Jelszó validálása - KIBŐVÍTVE .zip.cmpexport támogatással"""
        try:
            # .zip.cmpexport fájl esetén nincs jelszó teszt szükséges
            if os.path.isfile(self.input_dir) and self.input_dir.endswith('.zip.cmpexport'):
                return True

            # Keresés minden támogatott titkosított kiterjesztésben
            supported_extensions = list(self.extension_map.keys())
            supported_extensions.remove('.zip.cmpexport')  # Backup fájl nem tesztelhető

            for filename in os.listdir(self.input_dir):
                file_ext = os.path.splitext(filename)[1].lower()

                if file_ext in supported_extensions:
                    file_path = os.path.join(self.input_dir, filename)
                    cipher = self.create_cipher()
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read(16)
                    decrypted_data = cipher.decrypt(encrypted_data)
                    header = binascii.hexlify(decrypted_data).decode("utf8")

                    # Különböző fájltípusok header ellenőrzése
                    if (header.startswith("ffd8ff") or  # JPEG
                        header.startswith("89504e") or  # PNG
                        header.startswith("474946") or  # GIF
                        header.startswith("424d") or    # BMP
                        header.startswith("000000") or  # Video files
                        len(decrypted_data) > 0):       # Bármilyen dekriptált adat
                        return True
            return False
        except Exception as e:
            error_msg = f"{self.lang.get_text('password_test_error')}: {str(e)}"
            self.status_updated.emit(error_msg)
            return False

    def handle_cmpexport_file(self, zip_path, output_dir):
        """
        ÚJ: .zip.cmpexport fájl teljes feldolgozása
        Sort.db alapú mapping + intelligens névgenerálás
        """
        try:
            # 1. Temp mappa létrehozása
            temp_dir = os.path.join(os.path.dirname(zip_path), "temp_cmpexport")
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            os.makedirs(temp_dir, exist_ok=True)

            self.status_updated.emit(f"{self.lang.get_text('cmpexport_detected')}: {os.path.basename(zip_path)}")

            # 2. ZIP kicsomagolás
            self.status_updated.emit(self.lang.get_text('extracting_zip'))
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            # 3. Sort.db elemzés
            self.status_updated.emit(self.lang.get_text('analyzing_sortdb'))
            file_mapping = self.analyze_sort_db(temp_dir)

            # 4. .encrypt mappa dekriptálása
            self.status_updated.emit(self.lang.get_text('decrypting_folder'))
            encrypt_dir = os.path.join(temp_dir, ".encrypt")

            if not os.path.exists(encrypt_dir):
                raise Exception(f".encrypt mappa nem található: {encrypt_dir}")

            success_count = self.decrypt_encrypt_folder(encrypt_dir, output_dir, file_mapping)

            # 5. Mappák átnevezése időbélyeg alapján
            self.status_updated.emit(self.lang.get_text('folder_rename'))
            self.rename_output_folders(output_dir)

            # 6. Temp mappa takarítása
            self.status_updated.emit(self.lang.get_text('cleanup_temp'))
            shutil.rmtree(temp_dir)

            return success_count > 0, f"1 {self.lang.get_text('backup_processed')} ({success_count} fájl)"

        except Exception as e:
            error_msg = f"Backup feldolgozási hiba: {str(e)}"
            self.status_updated.emit(error_msg)

            # Cleanup hiba esetén is
            if 'temp_dir' in locals() and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass

            return False, error_msg

    def analyze_sort_db(self, temp_dir):
        """Sort.db elemzés fájlnév mapping kinyeréséhez - KIBŐVÍTVE dátum támogatással"""
        sort_db_path = os.path.join(temp_dir, "sort.db")
        file_mapping = {}

        if not os.path.exists(sort_db_path):
            self.status_updated.emit("sort.db nem található - folytatás mapping nélkül")
            return file_mapping

        try:
            conn = sqlite3.connect(sort_db_path)
            cursor = conn.cursor()

            # sortorder tábla lekérdezése bővített mezőkkel
            try:
                cursor.execute("SELECT id, dir, sort, date_modified FROM sortorder ORDER BY sort")
            except sqlite3.OperationalError:
                # Ha nincs date_modified mező, csak az alapokat kérjük le
                cursor.execute("SELECT id, dir, sort FROM sortorder ORDER BY sort")

            rows = cursor.fetchall()

            for row in rows:
                if len(row) >= 3:
                    id_hash, dir_hash, sort_order = row[0], row[1], row[2]
                    date_modified = row[3] if len(row) > 3 else None

                    file_mapping[id_hash] = {
                        'directory': dir_hash,
                        'sort_order': int(sort_order),
                        'original_name': f"file_{sort_order:03d}",
                        'date_modified': date_modified
                    }

            conn.close()
            self.status_updated.emit(f"Sort.db: {len(file_mapping)} fájl mapping betöltve")

        except Exception as e:
            self.status_updated.emit(f"Sort.db elemzési hiba: {str(e)}")

        return file_mapping

    def decrypt_encrypt_folder(self, encrypt_dir, output_dir, file_mapping):
        """
        .encrypt mappa rekurzív dekriptálása
        KIBŐVÍTVE intelligens név- és dátumkezeléssel
        """
        success_count = 0
        total_count = 0
        processed_dirs = set()

        # Rekurzív fájl bejárás
        for root, dirs, files in os.walk(encrypt_dir):
            for file in files:
                if self.should_stop:
                    return success_count

                total_count += 1
                input_file_path = os.path.join(root, file)

                # Relatív útvonal az encrypt_dir-hez képest
                rel_path = os.path.relpath(input_file_path, encrypt_dir)

                # Fájlnév és kiterjesztés
                file_basename = os.path.splitext(file)[0]
                file_ext = os.path.splitext(file)[1]

                # Kimeneti könyvtár meghatározása
                if file_basename in file_mapping:
                    mapping_info = file_mapping[file_basename]
                    output_subdir = mapping_info['directory'].rstrip('/')
                    output_dir_path = os.path.join(output_dir, output_subdir)
                else:
                    # Mapping nélkül - relatív útvonal megtartása
                    output_dir_path = os.path.join(output_dir, os.path.dirname(rel_path))

                # Kimeneti könyvtár létrehozása
                os.makedirs(output_dir_path, exist_ok=True)

                # Temp fájl létrehozása dekriptáláshoz
                temp_file_name = f"temp_{file_basename}{file_ext}"
                temp_file_path = os.path.join(output_dir_path, temp_file_name)

                # Dekriptálás (EREDETI ALGORITMUS)
                try:
                    cipher = self.create_cipher()

                    with open(input_file_path, 'rb') as f:
                        encrypted_data = f.read()

                    decrypted_data = cipher.decrypt(encrypted_data)

                    with open(temp_file_path, 'wb') as f:
                        f.write(decrypted_data)

                    # Intelligens fájlnév generálás
                    self.status_updated.emit(self.lang.get_text('intelligent_naming'))
                    sort_order = file_mapping[file_basename]['sort_order'] if file_basename in file_mapping else total_count
                    intelligent_name = generate_intelligent_filename(file_mapping, file_basename, temp_file_path, sort_order)

                    # Végleges fájl útvonal
                    final_file_path = os.path.join(output_dir_path, intelligent_name)

                    # Átnevezés intelligens névre
                    os.rename(temp_file_path, final_file_path)

                    # Időbélyeg helyreállítás
                    self.status_updated.emit(self.lang.get_text('timestamp_restore'))
                    restore_file_timestamps(input_file_path, final_file_path, file_mapping, file_basename)

                    success_count += 1
                    processed_dirs.add(output_dir_path)
                    self.status_updated.emit(f"{self.lang.get_text('completed')}: {intelligent_name}")

                except Exception as e:
                    error_msg = f"{self.lang.get_text('error')} {file}: {str(e)}"
                    self.status_updated.emit(error_msg)

                    # Temp fájl törlése hiba esetén
                    if os.path.exists(temp_file_path):
                        try:
                            os.remove(temp_file_path)
                        except:
                            pass

                # Haladás frissítése
                if total_count > 0:
                    progress = int(success_count / total_count * 100)
                    self.progress_updated.emit(min(progress, 100))

        return success_count

    def rename_output_folders(self, output_dir):
        """Kimeneti mappák átnevezése időbélyeg alapján"""
        try:
            # Almappák keresése és átnevezése
            for item in os.listdir(output_dir):
                item_path = os.path.join(output_dir, item)
                if os.path.isdir(item_path):
                    rename_folder_by_timestamps(item_path)
        except Exception as e:
            self.status_updated.emit(f"Mappa átnevezési hiba: {str(e)}")

    def process_files(self):
        """Fájlok feldolgozása - HIBRID: .zip.cmpexport + egyedi fájlok"""

        # .zip.cmpexport fájl kezelése
        if os.path.isfile(self.input_dir) and self.input_dir.endswith('.zip.cmpexport'):
            return self.handle_cmpexport_file(self.input_dir, self.output_dir)

        # Kimeneti könyvtár létrehozása
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        # Támogatott titkosított fájlok keresése
        supported_extensions = list(self.extension_map.keys())
        supported_extensions.remove('.zip.cmpexport')  # Backup már kezelve
        files = []

        for f in os.listdir(self.input_dir):
            if os.path.isfile(os.path.join(self.input_dir, f)):
                file_ext = os.path.splitext(f)[1].lower()
                if file_ext in supported_extensions:
                    files.append(f)

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

                # Dekriptálás (EREDETI ALGORITMUS)
                cipher = self.create_cipher()
                with open(input_path, "rb") as f:
                    decrypted_data = cipher.decrypt(f.read())

                # Temp fájl létrehozása
                basename, ext = os.path.splitext(filename)
                temp_filename = f"temp_{basename}{ext}"
                temp_path = os.path.join(self.output_dir, temp_filename)

                # Temp fájl írása
                with open(temp_path, "wb") as f:
                    f.write(decrypted_data)

                # Intelligens névgenerálás
                self.status_updated.emit(self.lang.get_text('intelligent_naming'))
                intelligent_name = generate_intelligent_filename(None, None, temp_path, i + 1)
                final_path = os.path.join(self.output_dir, intelligent_name)

                # Átnevezés
                os.rename(temp_path, final_path)

                # Időbélyeg helyreállítás
                self.status_updated.emit(self.lang.get_text('timestamp_restore'))
                restore_file_timestamps(input_path, final_path)

                successful_count += 1
                completed_msg = f"{self.lang.get_text('completed')}: {intelligent_name}"
                self.status_updated.emit(completed_msg)

            except Exception as e:
                error_msg = f"{self.lang.get_text('error')} {filename}: {str(e)}"
                self.status_updated.emit(error_msg)

                # Temp fájl törlése hiba esetén
                temp_path = os.path.join(self.output_dir, f"temp_{os.path.splitext(filename)[0]}{os.path.splitext(filename)[1]}")
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass

            # Haladás frissítése
            progress = int((i + 1) / len(files) * 100)
            self.progress_updated.emit(progress)

        # Kimeneti mappa átnevezése (ha van egyedi fájl)
        if successful_count > 0:
            self.status_updated.emit(self.lang.get_text('folder_rename'))
            rename_folder_by_timestamps(self.output_dir)

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
    """Fő alkalmazás ablak - KIBŐVÍTVE Pro funkciókkal"""

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
        self.setWindowIcon(QIcon('icon.png'))
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

        # Cím - 22px betűmérettel
        self.title = QLabel(self.lang.get_text("app_title"))
        self.title.setStyleSheet("color: #ffffff; margin-bottom: 15px; font-size: 22px; font-weight: bold;")
        header_layout.addWidget(self.title)

        # Spacer a középen
        header_layout.addStretch()

        # Nyelvválasztó a jobb oldalon - toggle design
        self.language_selector = QWidget()
        self.language_selector.setMaximumWidth(120)
        self.language_selector.setMaximumHeight(35)
        self.language_selector.setObjectName("languageSelector")

        # Layout a toggle-hoz
        selector_layout = QHBoxLayout(self.language_selector)
        selector_layout.setContentsMargins(0, 0, 0, 0)
        selector_layout.setSpacing(0)

        # Magyar gomb (bal oldal)
        self.hu_button = QPushButton("HU")
        self.hu_button.setCheckable(True)
        self.hu_button.setChecked(True)
        self.hu_button.clicked.connect(lambda: self.switch_language("hu"))
        self.hu_button.setObjectName("huButton")
        self.hu_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        # Angol gomb (jobb oldal)
        self.en_button = QPushButton("EN")
        self.en_button.setCheckable(True)
        self.en_button.clicked.connect(lambda: self.switch_language("en"))
        self.en_button.setObjectName("enButton")
        self.en_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        selector_layout.addWidget(self.hu_button)
        selector_layout.addWidget(self.en_button)

        header_layout.addWidget(self.language_selector)
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

        # Kezdeti állapot beállítása
        self.start_btn.setEnabled(False)
        self.start_btn.setText(self.lang.get_text("start_button") + " - Nincs fájl kijelölve")

        # Kimeneti tallózó gomb kezdetben letiltva
        self.output_browse.setEnabled(False)

        self.show()

    def create_file_group(self):
        """Fájl beállítások csoport"""
        group = QGroupBox(self.lang.get_text("folders_group"))
        layout = QVBoxLayout(group)

        # Bemenet
        input_layout = QHBoxLayout()
        self.input_label = QLabel(self.lang.get_text("input_label"))
        input_layout.addWidget(self.input_label)

        self.input_path = QLineEdit()
        self.input_path.setReadOnly(True)
        self.input_path.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.input_path.setStyleSheet(self.input_path.styleSheet() + "background-color: #404040;")
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
        self.output_path.setReadOnly(True)
        self.output_path.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.output_path.setStyleSheet(self.output_path.styleSheet() + "background-color: #404040;")
        self.output_path.setPlaceholderText(self.lang.get_text("output_placeholder"))

        self.output_browse = QPushButton(self.lang.get_text("browse_button"))
        self.output_browse.setEnabled(False)  # Alapból letiltva
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

    def switch_language(self, lang_code):
        """Nyelv váltás toggle gombokkal"""
        self.lang.set_language(lang_code)

        # Gombok állapotának frissítése
        self.hu_button.setChecked(lang_code == "hu")
        self.en_button.setChecked(lang_code == "en")

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
        """Sötét téma CSS"""
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

            /* Nyelvválasztó toggle design */
            QWidget#languageSelector {
                background-color: #3c3c3c;
                border: 2px solid #555555;
                border-radius: 18px;
                padding: 2px;
            }

            QPushButton#huButton, QPushButton#enButton {
                background-color: transparent;
                color: #cccccc;
                border: none;
                border-radius: 15px;
                padding: 6px 12px;
                font-size: 12px;
                font-weight: bold;
                min-width: 25px;
                min-height: 25px;
                margin: 1px;
                outline: none;
            }

            QPushButton#huButton:focus, QPushButton#enButton:focus {
                border: none !important;
                outline: none !important;
                background-color: transparent;
            }

            QPushButton#huButton:checked, QPushButton#enButton:checked {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #5a7ebf,
                    stop: 0.5 #4a6ea9,
                    stop: 1 #3a5e99
                );
                color: #ffffff;
                border: none !important;
                outline: none !important;
            }

            QPushButton#huButton:checked:focus, QPushButton#enButton:checked:focus {
                border: none !important;
                outline: none !important;
            }

            QPushButton#huButton:hover:!checked, QPushButton#enButton:hover:!checked {
                background-color: #4a4a4a;
                color: #ffffff;
                border: none;
                outline: none;
            }

            /* Letiltott tallózó gomb stílus */
            QPushButton:disabled {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #3a3a3a,
                    stop: 0.5 #2a2a2a,
                    stop: 1 #1a1a1a
                );
                color: #666666;
                border: 2px solid #333333;
            }
        """

    def log_message(self, message):
        """Napló üzenet"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        self.log_text.append(formatted)
        logging.info(message)

    def browse_input(self):
        """
        Bemeneti mappa vagy fájl kiválasztás 
        KIBŐVÍTVE .zip.cmpexport támogatással
        """
        # Fájl és mappa választás lehetősége
        input_path, _ = QFileDialog.getOpenFileName(
            self, 
            self.lang.get_text("input_folder_dialog"),
            "",
            "LockMyPix Files (*.zip.cmpexport *.6zu *.vp3 *.vo1 *.v27 *.vb9 *.v77 *.v78);;All Files (*)"
        )

        # Ha nem választott fájlt, próbáljunk mappát
        if not input_path:
            input_path = QFileDialog.getExistingDirectory(
                self, 
                self.lang.get_text("input_folder_dialog")
            )

        if input_path:
            self.input_path.setText(input_path)

            # Automatikus kimeneti mappa meghatározás
            if input_path.endswith('.zip.cmpexport'):
                # .zip.cmpexport fájl esetén
                output_dir = os.path.join(os.path.dirname(input_path), "decrypted_backup")
                log_msg = f"{self.lang.get_text('input_selected')}: {os.path.basename(input_path)} (LockMyPix backup)"
            else:
                # Mappa vagy egyedi fájl esetén
                if os.path.isfile(input_path):
                    output_dir = os.path.join(os.path.dirname(input_path), "decrypted")
                    log_msg = f"{self.lang.get_text('input_selected')}: {os.path.basename(input_path)}"
                else:
                    output_dir = os.path.join(input_path, "decrypted")
                    log_msg = f"{self.lang.get_text('input_selected')}: {input_path}"

            self.output_path.setText(output_dir)
            self.log_message(log_msg)

            # Kimeneti tallózó gomb aktiválása
            self.output_browse.setEnabled(True)

            # Támogatott fájlok ellenőrzése
            self.check_supported_files_and_update_button()

    def check_supported_files_and_update_button(self):
        """
        Ellenőrzi hogy van-e támogatott fájl a bemenetben
        KIBŐVÍTVE minden támogatott kiterjesztéssel és .zip.cmpexport-tal
        """
        input_path = self.input_path.text().strip()
        if not input_path:
            self.start_btn.setEnabled(False)
            self.start_btn.setText(self.lang.get_text("start_button") + " - Nincs fájl")
            self.output_browse.setEnabled(False)
            return

        # .zip.cmpexport fájl ellenőrzése
        if os.path.isfile(input_path) and input_path.endswith('.zip.cmpexport'):
            if os.path.exists(input_path):
                self.start_btn.setEnabled(True)
                self.start_btn.setText(self.lang.get_text("start_button"))
                self.log_message(f"LockMyPix backup fájl észlelve: {os.path.basename(input_path)}")
            else:
                self.start_btn.setEnabled(False)
                self.start_btn.setText(self.lang.get_text("start_button") + " - Fájl nem létezik")
            return

        # Egyedi titkosított fájl ellenőrzése
        if os.path.isfile(input_path):
            file_ext = os.path.splitext(input_path)[1].lower()
            # Extension mapping betöltése
            extension_map = {
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

            if file_ext in extension_map:
                self.start_btn.setEnabled(True)
                self.start_btn.setText(self.lang.get_text("start_button"))
                self.log_message(f"Támogatott titkosított fájl: {os.path.basename(input_path)} ({file_ext})")
            else:
                self.start_btn.setEnabled(False)
                self.start_btn.setText(self.lang.get_text("start_button") + " - Nem támogatott fájl")
            return

        # Mappa ellenőrzése támogatott fájlokra
        if not os.path.exists(input_path):
            self.start_btn.setEnabled(False)
            self.start_btn.setText(self.lang.get_text("start_button") + " - Nincs mappa")
            self.output_browse.setEnabled(False)
            return

        # Extension mapping betöltése
        extension_map = {
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

        supported_extensions = list(extension_map.keys())

        # Keressünk támogatott titkosított fájlokat a mappában
        has_supported_files = False
        total_count = 0
        extension_counts = {}

        try:
            files = os.listdir(input_path)
            for file in files:
                file_path = os.path.join(input_path, file)
                # Csak fájlokat vizsgálunk
                if os.path.isfile(file_path):
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext in supported_extensions:
                        has_supported_files = True
                        total_count += 1
                        extension_counts[file_ext] = extension_counts.get(file_ext, 0) + 1
        except Exception as e:
            self.log_message(f"Hiba a mappa ellenőrzésekor: {str(e)}")
            self.start_btn.setEnabled(False)
            return

        # Start gomb állapotának frissítése
        if has_supported_files:
            self.start_btn.setEnabled(True)
            self.start_btn.setText(self.lang.get_text("start_button"))

            # Részletes statisztika naplózása
            ext_stats = ", ".join([f"{ext}: {count}" for ext, count in extension_counts.items()])
            log_msg = f"Talált támogatott fájlok: {total_count} db ({ext_stats})"
            self.log_message(log_msg)
        else:
            self.start_btn.setEnabled(False)
            self.start_btn.setText(self.lang.get_text("start_button") + " - Nincs támogatott fájl")
            supported_ext_list = ", ".join(supported_extensions[:10]) + "..." if len(supported_extensions) > 10 else ", ".join(supported_extensions)
            self.log_message(f"Nem található támogatott fájl. Támogatott: .zip.cmpexport vagy {supported_ext_list}")

    def browse_output(self):
        """Kimeneti mappa kiválasztás"""
        folder = QFileDialog.getExistingDirectory(self, self.lang.get_text("output_folder_dialog"))
        if folder:
            self.output_path.setText(folder)
            log_msg = f"{self.lang.get_text('output_selected')}: {folder}"
            self.log_message(log_msg)

    def get_password(self):
        """Jelszó bekérése smart OK gombbal"""
        dialog = QInputDialog(self)
        dialog.setWindowTitle(self.lang.get_text("password_title"))
        dialog.setLabelText(self.lang.get_text("password_prompt"))

        # PyQt6/PyQt5 kompatibilis EchoMode beállítás
        try:
            from PyQt6.QtWidgets import QLineEdit
            dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
        except:
            try:
                from PyQt5.QtWidgets import QLineEdit
                dialog.setTextEchoMode(QLineEdit.Password)
            except:
                dialog.setTextEchoMode(2)  # 2 = Password mode

        # OK gomb megkeresése és kezdeti letiltása
        ok_button = None
        for child in dialog.findChildren(QPushButton):
            if child.text() in ["OK", "Ok"]:
                ok_button = child
                break

        if ok_button:
            ok_button.setEnabled(False)
            ok_button.setText("OK - Írd be a jelszót")

        # Jelszó mező megkeresése
        password_field = dialog.findChild(QLineEdit)

        def on_text_changed():
            """Jelszó mező változásakor hívódik meg"""
            if password_field and ok_button:
                has_text = bool(password_field.text().strip())
                ok_button.setEnabled(has_text)
                ok_button.setText("OK" if has_text else "OK - Írd be a jelszót")

        # Jelszó mező változásának figyelése
        if password_field:
            password_field.textChanged.connect(on_text_changed)

        # Kezdeti állapot beállítása
        on_text_changed()

        # Dialog megjelenítése
        try:
            if dialog.exec() == QInputDialog.DialogCode.Accepted:
                password = dialog.textValue().strip()
                if password:
                    return password
                else:
                    QMessageBox.warning(self, self.lang.get_text("error_title"), "A jelszó nem lehet üres!")
                    return None
        except:
            if dialog.exec_() == QInputDialog.Accepted:
                password = dialog.textValue().strip()
                if password:
                    return password
                else:
                    QMessageBox.warning(self, self.lang.get_text("error_title"), "A jelszó nem lehet üres!")
                    return None

        return None

    def start_decrypt(self):
        """Dekriptálás indítása"""
        input_path = self.input_path.text().strip()
        output_dir = self.output_path.text().strip()

        # Validálás
        if not input_path or not output_dir:
            QMessageBox.warning(self, self.lang.get_text("error_title"),
                               self.lang.get_text("missing_folders"))
            return

        # Fájl vagy mappa létezés ellenőrzése
        if not os.path.exists(input_path):
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
        self.worker = DecryptWorker(password, input_path, output_dir, self.lang)
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
