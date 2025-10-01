import sys
import os
import shutil
import tempfile
import logging
import binascii
import hashlib
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QLineEdit, QMessageBox,
    QProgressBar, QTextEdit, QFrame, QInputDialog
)

# -----------------------------------------------------------------------------
# A LockMyPix referencia kód decrypt.py-ból VÁLTOZATLANUL átvett részek:
# - extension_map
# - test_password
# - write_to_output
# Forrás: https://github.com/c-sleuth/lock-my-pix-android-decrypt/blob/main/decrypt.py
# -----------------------------------------------------------------------------
# [KEZDŐDIK - változatlan beemelés]
from Crypto.Cipher import AES
from Crypto.Util import Counter

# this is likely not a full list of the extensions possible
extension_map = {
    ".vp3": ".mp4",
    ".vo1": ".webm",
    ".v27": ".mpg",
    ".vb9": ".avi",
    ".v77": ".mov",
    ".v78": ".wmv",
    ".v82": ".dv",
    ".vz9": ".divx",
    ".vi3": ".ogv",
    ".v1u": ".h261",
    ".v6m": ".h264",
    ".6zu": ".jpg",
    ".tr7": ".gif",
    ".p5o": ".png",
    ".8ur": ".bmp",
    ".33t": ".tiff",  # this extension could also be .tif
    ".20i": ".webp",
    ".v93": ".heic",
    ".v91": ".flv",  # this key is linked to .flv and .eps
    ".v80": ".3gpp",
    ".vo4": ".ts",
    ".v99": ".mkv",
    ".vr2": ".mpeg",
    ".vv3": ".dpg",
    ".v81": ".rmvb",
    ".vz8": ".vob",
    ".wi2": ".asf",
    ".vi4": ".h263",
    ".v2u": ".f4v",
    ".v76": ".m4v",
    ".v75": ".ram",
    ".v74": ".rm",
    ".v3u": ".mts",
    ".v92": ".dng",
    ".r89": ".ps",
    ".v79": ".3gp",
}

def test_password(input_dir, password):
    for file in os.listdir(input_dir):
        if file.endswith(".6zu"):
            key = hashlib.sha1(password.encode()).digest()[:16]
            iv = key
            counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            encrypted_path = os.path.join(input_dir, os.fsdecode(file))
            with open(encrypted_path, "rb+") as enc_data:
                dec_data = cipher.decrypt(enc_data.read(16))
                header = binascii.hexlify(dec_data).decode("utf8")
                if header.startswith("ffd8ff"):
                    return True
                else:
                    logging.warning(f"{password} appears to be incorrect")
                    return False
    else:
        logging.warning("Cannot find a jpg file to test password")
        # Eredetileg itt interaktív y/n kérdés van, GUI-ban nem kérdezünk itt
        return False

def write_to_output(output_dir, filename, dec_data):
    basename, ext = os.path.splitext(filename)
    if extension_map.get(ext):
        filename += extension_map.get(ext)
    else:
        filename += ".unknown"
        logging.warning(f"File {filename} has an unknown extension")
    if not Path(output_dir).exists():
        logging.info(f"Creating output directory: {output_dir}")
        os.mkdir(output_dir)
    with open(os.path.join(output_dir, filename), "wb") as f:
        f.write(dec_data)
    logging.info(f"Decrypted file {filename} written to {output_dir}")
# [VÉGE - változatlan beemelés]
# -----------------------------------------------------------------------------

# GUI-hoz kiegészítő logger a panelhez
class QTextEditLogger(logging.Handler):
    def __init__(self, widget: QTextEdit):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        msg = self.format(record)
        self.widget.append(msg)

# Háttérszál a dekódoláshoz
class DecryptWorker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, input_file: str, output_dir: str, password: str):
        super().__init__()
        self.input_file = input_file
        self.output_dir = output_dir
        self.password = password
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        try:
            self.status.emit("Előkészítés...")
            self.progress.emit(5)

            # Ideiglenes mappa létrehozása a referencia test_password kompatibilitáshoz
            temp_dir = tempfile.mkdtemp(prefix="lmpx_gui_")
            try:
                # A kiválasztott fájlt ide másoljuk .6zu néven
                src = Path(self.input_file)
                if src.suffix.lower() != ".6zu":
                    self.finished.emit(False, "Csak .6zu kiterjesztésű fájl támogatott.")
                    return

                temp_file = Path(temp_dir) / src.name
                shutil.copy2(src, temp_file)

                if not self._running:
                    self.finished.emit(False, "Művelet megszakítva")
                    return

                self.status.emit("Jelszó ellenőrzése...")
                self.progress.emit(15)

                # Eredeti test_password használata (változatlan)
                ok = test_password(temp_dir, self.password)
                if not ok:
                    self.finished.emit(False, "Hibás jelszó vagy nem felismerhető 6zu tartalom.")
                    return

                self.status.emit("Fájl beolvasása...")
                self.progress.emit(30)

                with open(temp_file, "rb") as f:
                    enc = f.read()

                if not self._running:
                    self.finished.emit(False, "Művelet megszakítva")
                    return

                # Dekódolás a referencia logikájával (CTR, iv=key)
                self.status.emit("Dekódolás...")
                self.progress.emit(55)

                key = hashlib.sha1(self.password.encode()).digest()[:16]
                iv = key
                counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                cipher = AES.new(key, AES.MODE_CTR, counter=counter)

                # Nagyobb fájloknál szeletelve is lehetne, itt egyszerűen egyben
                dec_data = cipher.decrypt(enc)

                if not self._running:
                    self.finished.emit(False, "Művelet megszakítva")
                    return

                self.status.emit("Kimenet írása...")
                self.progress.emit(80)

                # Eredeti write_to_output hívása (változatlan)
                # A referencia write_to_output a filename kiterjesztés alapján dönt
                # Itt a kiválasztott fájl nevét adjuk át (pl. foto.6zu)
                write_to_output(self.output_dir, src.name, dec_data)

                self.progress.emit(100)
                self.status.emit("Kész")
                self.finished.emit(True, "Sikeres dekódolás.")
            finally:
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass

        except Exception as e:
            logging.exception("Dekódolási hiba")
            self.finished.emit(False, f"Hiba történt: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("6zu AES Dekódoló – Modern")
        self.setMinimumSize(760, 520)

        self.input_file: str | None = None
        self.output_dir: str | None = None
        self.worker: DecryptWorker | None = None

        self._build_ui()
        self._setup_logging()
        self._apply_modern_style()

    def _build_ui(self):
        cw = QWidget()
        self.setCentralWidget(cw)
        root = QVBoxLayout(cw)
        root.setContentsMargins(28, 28, 28, 28)
        root.setSpacing(18)

        title = QLabel("6zu AES Dekódoló")
        f = QFont()
        f.setPointSize(18)
        f.setBold(True)
        title.setFont(f)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(title)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        root.addWidget(line)

        # Bemenet blokk
        file_group = QFrame()
        file_group.setFrameStyle(QFrame.Shape.StyledPanel)
        fg = QVBoxLayout(file_group)

        lbl_in = QLabel("🔒 Bemeneti fájl (.6zu)")
        lbl_in.setFont(QFont("", 10, QFont.Weight.Bold))
        fg.addWidget(lbl_in)

        fh = QHBoxLayout()
        self.file_label = QLabel("Nincs fájl kiválasztva…")
        self.file_label.setStyleSheet("color:#666; font-style:italic;")
        self.btn_browse = QPushButton("📁 Tallózás")
        self.btn_browse.clicked.connect(self._choose_file)
        fh.addWidget(self.file_label, 1)
        fh.addWidget(self.btn_browse)
        fg.addLayout(fh)

        root.addWidget(file_group)

        # Kimenet blokk
        out_group = QFrame()
        out_group.setFrameStyle(QFrame.Shape.StyledPanel)
        og = QVBoxLayout(out_group)

        lbl_out = QLabel("📂 Kimeneti mappa")
        lbl_out.setFont(QFont("", 10, QFont.Weight.Bold))
        og.addWidget(lbl_out)

        oh = QHBoxLayout()
        self.output_label = QLabel("Nincs mappa kiválasztva…")
        self.output_label.setStyleSheet("color:#666; font-style:italic;")
        self.btn_out = QPushButton("📂 Mappa választás")
        self.btn_out.clicked.connect(self._choose_output)
        oh.addWidget(self.output_label, 1)
        oh.addWidget(self.btn_out)
        og.addLayout(oh)

        root.addWidget(out_group)

        # Gombok
        btns = QFrame()
        hb = QHBoxLayout(btns)
        self.btn_start = QPushButton("🚀 Indít")
        self.btn_start.setEnabled(False)
        self.btn_start.clicked.connect(self._start)
        self.btn_stop = QPushButton("⏹ Leállít")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        hb.addWidget(self.btn_start)
        hb.addWidget(self.btn_stop)
        root.addWidget(btns)

        # Haladás/státusz
        prog_group = QFrame()
        pg = QVBoxLayout(prog_group)
        self.status_label = QLabel("Készen áll…")
        self.progress = QProgressBar()
        self.progress.setValue(0)
        pg.addWidget(self.status_label)
        pg.addWidget(self.progress)
        root.addWidget(prog_group)

        # Log
        log_group = QFrame()
        lg = QVBoxLayout(log_group)
        lh = QHBoxLayout()
        l_title = QLabel("📋 Működési napló")
        l_title.setFont(QFont("", 10, QFont.Weight.Bold))
        self.btn_log = QPushButton("👁 Log megjelenítése")
        self.btn_log.clicked.connect(self._toggle_log)
        lh.addWidget(l_title)
        lh.addStretch()
        lh.addWidget(self.btn_log)
        lg.addLayout(lh)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(180)
        self.log_view.hide()
        lg.addWidget(self.log_view)
        root.addWidget(log_group)

    def _apply_modern_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QFrame {
                background: #fff;
                border: 1px solid #e0e0e0;
                border-radius: 10px;
                padding: 14px;
            }
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #1565C0; }
            QPushButton:disabled { background-color: #c9c9c9; color:#777; }
            QProgressBar {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                text-align: center;
                height: 18px;
                background: #fafafa;
            }
            QProgressBar::chunk {
                background-color: #43A047;
                border-radius: 4px;
            }
            QTextEdit {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                font-family: Consolas, monospace;
                background: #fcfcfc;
            }
        """)

    def _setup_logging(self):
        self.logger = logging.getLogger("lmpx_gui")
        self.logger.setLevel(logging.INFO)
        # File + GUI log
        fh = logging.FileHandler("LockMyPix_decryption_log.log", encoding="utf-8")
        fh.setLevel(logging.INFO)
        fmt = logging.Formatter('[%(levelname)s] %(asctime)s %(message)s', datefmt='%d-%m-%Y %H:%M:%S')
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)

        gui_handler = QTextEditLogger(self.log_view)
        gui_handler.setFormatter(fmt)
        self.logger.addHandler(gui_handler)

        self.logger.info("Alkalmazás elindult")

    def _choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "6zu fájl kiválasztása", "", "6zu fájlok (*.6zu)")
        if not path:
            return
        self.input_file = path
        self.file_label.setText(os.path.basename(path))
        self.file_label.setStyleSheet("color:#1976D2; font-weight:600;")
        # Alapértelmezett kimeneti mappa a bemenet mappája
        self.output_dir = str(Path(path).parent)
        self.output_label.setText(self.output_dir)
        self.output_label.setStyleSheet("color:#1976D2;")
        self.btn_start.setEnabled(True)
        self.logger.info(f"Kiválasztott bemeneti fájl: {path}")

    def _choose_output(self):
        base = self.output_dir or (str(Path(self.input_file).parent) if self.input_file else "")
        out = QFileDialog.getExistingDirectory(self, "Kimeneti mappa kiválasztása", base)
        if not out:
            return
        self.output_dir = out
        self.output_label.setText(out)
        self.output_label.setStyleSheet("color:#1976D2;")
        self.logger.info(f"Kimeneti mappa: {out}")

    def _start(self):
        if not self.input_file:
            QMessageBox.warning(self, "Figyelem", "Nincs kiválasztva bemeneti fájl.")
            return
        if Path(self.input_file).suffix.lower() != ".6zu":
            QMessageBox.warning(self, "Figyelem", "Csak .6zu kiterjesztésű fájl választható.")
            return
        if not self.output_dir:
            QMessageBox.warning(self, "Figyelem", "Nincs kiválasztva kimeneti mappa.")
            return

        # Jelszó bekérése
        password, ok = QInputDialog.getText(self, "🔑 Jelszó", "Add meg a jelszót:", QLineEdit.EchoMode.Password)
        if not ok or not password:
            return

        # Indítás
        self.logger.info("Dekódolás indítása")
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress.setValue(0)
        self.status_label.setText("Indítás...")

        self.worker = DecryptWorker(self.input_file, self.output_dir, password)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.status.connect(self.status_label.setText)
        self.worker.finished.connect(self._done)
        self.worker.start()

    def _stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            self.logger.info("Művelet megszakítva")
            self.status_label.setText("Megszakítva")
            self.btn_stop.setEnabled(False)
            self.btn_start.setEnabled(True)

    def _done(self, ok: bool, msg: str):
        self.logger.info(msg)
        self.btn_stop.setEnabled(False)
        self.btn_start.setEnabled(True)
        if ok:
            self.progress.setValue(100)
            QMessageBox.information(self, "Siker", msg)
            self.status_label.setText("Kész")
        else:
            QMessageBox.warning(self, "Hiba", msg)
            self.status_label.setText("Hiba")

    def _toggle_log(self):
        if self.log_view.isVisible():
            self.log_view.hide()
            self.btn_log.setText("👁 Log megjelenítése")
        else:
            self.log_view.show()
            self.btn_log.setText("🙈 Log elrejtése")

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
