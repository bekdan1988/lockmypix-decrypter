import sys
import os
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

# -------------------------------------------------------------
# A LockMyPix referencia kód (decrypt.py) 3 RÉSZE FELHASZNÁLVA:
# - extension_map
# - test_password
# - write_to_output
# Forrás: c-sleuth/lock-my-pix-android-decrypt/decrypt.py
# -------------------------------------------------------------
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
            with open(encrypted_path, "rb+") as enc_
                dec_data = cipher.decrypt(enc_data.read(16))
                header = binascii.hexlify(dec_data).decode("utf8")
                if header.startswith("ffd8ff"):
                    return True
                else:
                    logging.warning(f"{password} appears to be incorrect")
                    return False
    else:
        logging.warning("Cannot find a jpg file to test password")
        # A referencia kódban itt interaktív y/n kérdés van; GUI-ban False-szal jelezzük,
        # hogy a jelszót nem tudtuk ellenőrizni (nincs .6zu tesztelhető fájl).
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
# -------------------------------------------------------------
# VÉGE: referencia kód felhasznált részek
# -------------------------------------------------------------

LOG_FILE = "LockMyPix_decryption_log.log"

class QTextEditLogger(logging.Handler):
    def __init__(self, widget: QTextEdit):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        msg = self.format(record)
        self.widget.append(msg)

def setup_logging(log_widget: QTextEdit | None = None):
    logger = logging.getLogger("lmpx_gui")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8", mode="w")
    fmt = logging.Formatter('[%(levelname)s] %(asctime)s %(message)s', datefmt='%d-%m-%Y %H:%M:%S')
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    if log_widget is not None:
        gui_handler = QTextEditLogger(log_widget)
        gui_handler.setFormatter(fmt)
        logger.addHandler(gui_handler)

    logger.info("Alkalmazás elindult")
    return logger

class DecryptThread(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, input_dir: str, output_dir: str, password: str):
        super().__init__()
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.password = password
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        try:
            logger = logging.getLogger("lmpx_gui")
            self.status.emit("Jelszó ellenőrzése...")
            self.progress.emit(5)

            ok = test_password(self.input_dir, self.password)
            if not ok:
                self.finished.emit(False, "Hibás jelszó vagy nem található tesztelhető .6zu fájl.")
                return

            files = [f for f in os.listdir(self.input_dir) if f.lower().endswith(".6zu")]
            total = len(files)
            if total == 0:
                self.finished.emit(False, "A bemeneti mappában nincs .6zu fájl.")
                return

            Path(self.output_dir).mkdir(parents=True, exist_ok=True)

            processed = 0
            self.status.emit("Dekódolás folyamatban...")
            for name in files:
                if not self._running:
                    self.finished.emit(False, "Művelet megszakítva.")
                    return

                in_path = os.path.join(self.input_dir, name)
                with open(in_path, "rb") as enc:
                    enc_data = enc.read()

                key = hashlib.sha1(self.password.encode()).digest()[:16]
                iv = key
                counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                cipher = AES.new(key, AES.MODE_CTR, counter=counter)
                dec_data = cipher.decrypt(enc_data)

                write_to_output(self.output_dir, name, dec_data)

                processed += 1
                pct = 5 + int(95 * (processed / total))
                self.progress.emit(pct)

            self.status.emit("Kész")
            self.finished.emit(True, f"Sikeres dekódolás. {processed} fájl feldolgozva.")
        except Exception as e:
            logging.getLogger("lmpx_gui").exception("Hiba történt")
            self.finished.emit(False, f"Hiba történt: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("6zu AES Dekódoló – Modern")
        self.setMinimumSize(800, 560)

        self.input_dir: str | None = None
        self.output_dir: str | None = None
        self.worker: DecryptThread | None = None

        self._build_ui()
        self.logger = setup_logging(self.log_view)
        self._apply_style()

    def _build_ui(self):
        cw = QWidget()
        self.setCentralWidget(cw)
        root = QVBoxLayout(cw)
        root.setContentsMargins(26, 26, 26, 26)
        root.setSpacing(16)

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

        in_group = QFrame()
        ig = QVBoxLayout(in_group)
        lbl_in = QLabel("📁 Bemeneti mappa (.6zu fájlokkal)")
        lbl_in.setFont(QFont("", 10, QFont.Weight.Bold))
        ig.addWidget(lbl_in)
        ih = QHBoxLayout()
        self.in_label = QLabel("Nincs mappa kiválasztva…")
        self.in_label.setStyleSheet("color:#666; font-style:italic;")
        self.btn_in = QPushButton("Tallózás…")
        self.btn_in.clicked.connect(self._choose_input_dir)
        ih.addWidget(self.in_label, 1)
        ih.addWidget(self.btn_in)
        ig.addLayout(ih)
        root.addWidget(in_group)

        out_group = QFrame()
        og = QVBoxLayout(out_group)
        lbl_out = QLabel("📂 Kimeneti mappa (alapértelmezés: bemeneti/unlocked)")
        lbl_out.setFont(QFont("", 10, QFont.Weight.Bold))
        og.addWidget(lbl_out)
        oh = QHBoxLayout()
        self.out_label = QLabel("Nincs mappa kiválasztva…")
        self.out_label.setStyleSheet("color:#666; font-style:italic;")
        self.btn_out = QPushButton("Mappa választás…")
        self.btn_out.clicked.connect(self._choose_output_dir)
        oh.addWidget(self.out_label, 1)
        oh.addWidget(self.btn_out)
        og.addLayout(oh)
        root.addWidget(out_group)

        btns = QFrame()
        bh = QHBoxLayout(btns)
        self.btn_start = QPushButton("🚀 Indít")
        self.btn_start.setEnabled(False)
        self.btn_start.clicked.connect(self._start)
        self.btn_stop = QPushButton("⏹ Leállít")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        self.btn_log = QPushButton("📜 Napló megnyitása")
        self.btn_log.clicked.connect(self._open_log)
        bh.addWidget(self.btn_start)
        bh.addWidget(self.btn_stop)
        bh.addStretch()
        bh.addWidget(self.btn_log)
        root.addWidget(btns)

        prog = QFrame()
        pg = QVBoxLayout(prog)
        self.status_label = QLabel("Készen áll…")
        self.progress = QProgressBar()
        self.progress.setValue(0)
        pg.addWidget(self.status_label)
        pg.addWidget(self.progress)
        root.addWidget(prog)

        log_group = QFrame()
        lg = QVBoxLayout(log_group)
        ltitle = QLabel("Működési napló")
        ltitle.setFont(QFont("", 10, QFont.Weight.Bold))
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(180)
        lg.addWidget(ltitle)
        lg.addWidget(self.log_view)
        root.addWidget(log_group)

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f5f5f7; }
            QFrame {
                background: #fff;
                border: 1px solid #e5e7eb;
                border-radius: 10px;
                padding: 14px;
            }
            QPushButton {
                background-color: #2563eb;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 8px;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:disabled { background-color: #cbd5e1; color:#64748b; }
            QProgressBar {
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                background: #f8fafc;
                height: 18px;
                text-align: center;
            }
            QProgressBar::chunk { background-color: #10b981; border-radius: 6px; }
            QTextEdit {
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                background: #fafafa;
                font-family: Consolas, monospace;
            }
        """)

    def _choose_input_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Bemeneti mappa kiválasztása", "")
        if not path:
            return
        self.input_dir = path
        self.in_label.setText(path)
        self.in_label.setStyleSheet("color:#2563eb; font-weight:600;")
        default_out = os.path.join(path, "unlocked")
        self.output_dir = default_out
        self.out_label.setText(default_out)
        self.out_label.setStyleSheet("color:#2563eb;")
        has_6zu = any(f.lower().endswith(".6zu") for f in os.listdir(path))
        self.btn_start.setEnabled(has_6zu)
        if not has_6zu:
            QMessageBox.information(self, "Információ", "A mappában nem található .6zu fájl.")
        logging.getLogger("lmpx_gui").info(f"Bemeneti mappa: {path}")
        logging.getLogger("lmpx_gui").info(f"Alapértelmezett kimenet: {default_out}")

    def _choose_output_dir(self):
        base = self.output_dir or (self.input_dir or "")
        out = QFileDialog.getExistingDirectory(self, "Kimeneti mappa kiválasztása", base)
        if not out:
            return
        self.output_dir = out
        self.out_label.setText(out)
        self.out_label.setStyleSheet("color:#2563eb;")
        logging.getLogger("lmpx_gui").info(f"Kimeneti mappa: {out}")

    def _start(self):
        if not self.input_dir:
            QMessageBox.warning(self, "Figyelem", "Nincs kiválasztva bemeneti mappa.")
            return
        if not self.output_dir:
            QMessageBox.warning(self, "Figyelem", "Nincs kijelölt kimeneti mappa.")
            return

        try:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            QMessageBox.critical(self, "Hiba", f"Nem hozható létre a kimeneti mappa: {e}")
            return

        password, ok = QInputDialog.getText(self, "🔑 Jelszó", "Add meg a jelszót:", QLineEdit.EchoMode.Password)
        if not ok or not password:
            return

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress.setValue(0)
        self.status_label.setText("Indítás…")
        logging.getLogger("lmpx_gui").info("Dekódolás indítása")

        self.worker = DecryptThread(self.input_dir, self.output_dir, password)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.status.connect(self.status_label.setText)
        self.worker.finished.connect(self._done)
        self.worker.start()

    def _stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            logging.getLogger("lmpx_gui").info("Művelet megszakítva")
            self.status_label.setText("Megszakítva")
            self.btn_stop.setEnabled(False)
            self.btn_start.setEnabled(True)

    def _done(self, ok: bool, msg: str):
        logging.getLogger("lmpx_gui").info(msg)
        self.btn_stop.setEnabled(False)
        self.btn_start.setEnabled(True)
        if ok:
            self.progress.setValue(100)
            QMessageBox.information(self, "Siker", msg)
            self.status_label.setText("Kész")
        else:
            QMessageBox.warning(self, "Hiba", msg)
            self.status_label.setText("Hiba")

    def _open_log(self):
        path = Path(LOG_FILE).resolve()
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
        except Exception:
            QMessageBox.information(self, "Napló", f"A napló itt található: {path}")

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
