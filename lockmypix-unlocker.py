import sys
import os
import io
import logging
from typing import Optional, Tuple

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QLineEdit, QProgressBar, QInputDialog, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES

# ---------------------------
# extension_map + felismerés
# ---------------------------
# A kiterjesztés-hozzárendelés a dekódolt bájtok "magic" fejlécéből történik,
# a gyakori formátumok lefedésével (LockMyPix decrypt.py elv alapján).
extension_map = {
    b"\x89PNG\r\n\x1a\n": ".png",
    b"\xff\xd8\xff": ".jpg",
    b"GIF87a": ".gif",
    b"GIF89a": ".gif",
    b"%PDF": ".pdf",
    b"\x50\x4B\x03\x04": ".zip",
    b"BM": ".bmp",
    b"OggS": ".ogg",
    b"RIFF": ".riff",  # majd finomítjuk WEBP/WAV szerint
    b"\x1A\x45\xDF\xA3": ".mkv",  # Matroska
    b"ID3": ".mp3",
}

def guess_extension(first_bytes: bytes) -> str:
    # Speciális vizsgálatok
    if len(first_bytes) >= 12 and first_bytes[4:8] == b"ftyp":
        return ".mp4"
    if first_bytes.startswith(b"RIFF"):
        # WEBP vs WAV
        if len(first_bytes) >= 12 and first_bytes[8:12] == b"WEBP":
            return ".webp"
        if len(first_bytes) >= 12 and first_bytes[8:12] == b"WAVE":
            return ".wav"
        return ".riff"
    # Direkt prefix egyezések
    for sig, ext in extension_map.items():
        if first_bytes.startswith(sig):
            return ext
    # Alapértelmezett bináris
    return ".bin"

# ---------------------------
# write_to_output
# ---------------------------
def write_to_output(out_dir: str, base_name: str, temp_path: str, ext: str) -> str:
    """
    Temp fájl átnevezése ütközéskezeléssel, a kiterjesztés hozzárendelésével.
    """
    os.makedirs(out_dir, exist_ok=True)
    target = os.path.join(out_dir, base_name + ext)
    if not os.path.exists(target):
        os.replace(temp_path, target)
        return target
    # Ütközés esetén sorszámozás
    i = 1
    while True:
        candidate = os.path.join(out_dir, f"{base_name}_{i}{ext}")
        if not os.path.exists(candidate):
            os.replace(temp_path, candidate)
            return candidate
        i += 1

# ---------------------------
# test_password
# ---------------------------
def test_password(infile: str, password: str, log: logging.Logger) -> Tuple[bool, Optional[bytes]]:
    """
    Jelszó ellenőrzése: teljes visszafejtés memóriába és tag ellenőrzés.
    Siker esetén visszaadja a dekódolt bájtokat, különben (False, None).
    A fejléckiosztás: 32B salt, 12B nonce, 16B tag, utána ciphertext (LockMyPix minta).
    """
    try:
        with open(infile, "rb") as f:
            salt = f.read(32)
            nonce = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()
        key = scrypt(password.encode("utf-8"), salt, 32, N=2**18, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        log.info("test_password: sikeres tag verifikáció")
        return True, plaintext
    except Exception as e:
        log.error(f"test_password: hiba vagy rossz jelszó: {e}")
        return False, None

# ---------------------------
# Dekódoló munkaszál
# ---------------------------
class DecryptWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    stopped = pyqtSignal()

    def __init__(self, infile: str, outdir: str, password: str, log_path: str):
        super().__init__()
        self.infile = infile
        self.outdir = outdir
        self.password = password
        self._running = True
        # Logger beállítás
        self.logger = logging.getLogger(f"decrypt_logger_{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)

    def stop(self):
        self._running = False

    def run(self):
        try:
            self.logger.info(f"Indítás: infile={self.infile}, outdir={self.outdir}")
            ok, plaintext = test_password(self.infile, self.password, self.logger)
            if not ok or plaintext is None:
                self.error.emit("Hibás jelszó vagy sérült fájl!")
                return

            # Kimeneti temp fájl írása chunkokban, hogy legyen progress és megszakíthatóság
            base_name = os.path.splitext(os.path.basename(self.infile))[0]
            temp_path = os.path.join(self.outdir, base_name + ".partial")
            total = len(plaintext)
            written = 0
            first_bytes = plaintext[:64]

            with open(temp_path, "wb") as out:
                chunk_size = 64 * 1024
                stream = io.BytesIO(plaintext)
                while self._running:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    out.write(chunk)
                    written += len(chunk)
                    self.progress.emit(int(written / max(1, total) * 100))

            if not self._running:
                # Megszakítás – takarítás
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                finally:
                    self.logger.info("Művelet megszakítva a felhasználó által")
                    self.stopped.emit()
                    return

            # Kiterjesztés meghatározása és véglegesítés
            ext = guess_extension(first_bytes)
            final_path = write_to_output(self.outdir, base_name, temp_path, ext)
            self.logger.info(f"Sikeres dekódolás: {final_path}")
            self.finished.emit(f"Sikeres dekódolás: {os.path.basename(final_path)}")
        except Exception as e:
            self.logger.exception(f"Hiba futás közben: {e}")
            self.error.emit(f"Hiba: {e}")

# ---------------------------
# Modern PyQt6 UI
# ---------------------------
class ModernApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modern 6zu AES Dekóder")
        self.setStyleSheet("""
            QWidget { background-color: #243043; color: #F0F3F7; border-radius: 10px; font-size: 14px; }
            QLabel { font-weight: 600; }
            QPushButton {
                background-color: #5E77FC; color: #fff; padding: 9px 22px;
                border: none; border-radius: 10px; font-weight: 600;
            }
            QPushButton:disabled { background-color: #7f8c8d; color: #e0e0e0; }
            QLineEdit {
                background-color: #1f2a3a; color: #F0F3F7; border: 1px solid #5E77FC;
                border-radius: 6px; padding: 7px 8px;
            }
            QProgressBar {
                border: 1px solid #5E77FC; border-radius: 6px;
                text-align: center; background: #1f2a3a; color: #F0F3F7;
            }
            QProgressBar::chunk { background-color: #5E77FC; border-radius: 6px; }
        """)

        self.file_path = ""
        self.output_dir = ""
        self.worker: Optional[DecryptWorker] = None
        self.log_path = ""  # futáskor kerül beállításra

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Bemeneti fájl
        row1 = QHBoxLayout()
        self.input_edit = QLineEdit(readOnly=True)
        btn_browse = QPushButton("Tallóz")
        btn_browse.clicked.connect(self.pick_file)
        row1.addWidget(QLabel("Bemeneti fájl:"))
        row1.addWidget(self.input_edit)
        row1.addWidget(btn_browse)
        layout.addLayout(row1)

        # Kimeneti mappa
        row2 = QHBoxLayout()
        self.output_edit = QLineEdit(readOnly=True)
        btn_out = QPushButton("Kimeneti mappa")
        btn_out.clicked.connect(self.pick_output)
        row2.addWidget(QLabel("Kimeneti mappa:"))
        row2.addWidget(self.output_edit)
        row2.addWidget(btn_out)
        layout.addLayout(row2)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Gombok
        row3 = QHBoxLayout()
        self.start_btn = QPushButton("Indít")
        self.start_btn.clicked.connect(self.start_decrypt)
        self.stop_btn = QPushButton("Leállít")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_decrypt)
        row3.addWidget(self.start_btn)
        row3.addWidget(self.stop_btn)
        layout.addLayout(row3)

        # Üzenetek
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Válassz .6zu fájlt", "", "6zu Files (*.6zu)"
        )
        if path:
            self.file_path = path
            self.input_edit.setText(path)
            # Alapértelmezett kimeneti mappa a bemeneti mappa
            out_dir = os.path.dirname(path)
            self.output_dir = out_dir
            self.output_edit.setText(out_dir)

    def pick_output(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "Kimeneti mappa kiválasztása",
            self.output_dir if self.output_dir else ""
        )
        if dir_path:
            self.output_dir = dir_path
            self.output_edit.setText(dir_path)

    def start_decrypt(self):
        if not self.file_path or not self.file_path.endswith(".6zu"):
            QMessageBox.warning(self, "Hiba", "Csak .6zu fájl választható ki!")
            return
        if not self.output_dir:
            QMessageBox.warning(self, "Hiba", "Válassz kimeneti mappát!")
            return

        # Jelszó bekérése
        passwd, ok = QInputDialog.getText(
            self, "Jelszó szükséges",
            "Add meg a titkosításhoz használt jelszót:",
            QLineEdit.EchoMode.Password
        )
        if not ok or not passwd:
            return

        # Logfájl
        self.log_path = os.path.join(self.output_dir, "6zu_decrypt.log")

        # Állapot
        self.progress_bar.setValue(0)
        self.status_label.setText("Dekódolás folyamatban...")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        # Munkaszál indítása
        self.worker = DecryptWorker(self.file_path, self.output_dir, passwd, self.log_path)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.stopped.connect(self.on_stopped)
        self.worker.start()

    def stop_decrypt(self):
        if self.worker:
            self.worker.stop()
            self.stop_btn.setEnabled(False)
            self.status_label.setText("Leállítás folyamatban...")

    def on_finished(self, msg: str):
        self.status_label.setText(msg)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_error(self, msg: str):
        self.status_label.setText(msg)
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_stopped(self):
        self.status_label.setText("A művelet megszakítva.")
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = ModernApp()
    w.resize(720, 240)
    w.show()
    sys.exit(app.exec())
