import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import argparse
import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QLineEdit, QProgressBar, QInputDialog, QMessageBox)
from PyQt6.QtCore import QThread, pyqtSignal

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

class DecryptExtractThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    stopped = pyqtSignal()
    
    def __init__(self, infile, outdir, password):
        super().__init__()
        self.infile = infile
        self.outdir = outdir
        self.password = password
        self._is_running = True

    def run(self):
        try:
            with open(self.infile, "rb+") as f:
                dec_data = cipher.decrypt(f.read(16))
                header = binascii.hexlify(dec_data).decode("utf8")
            key = hashlib.sha1(password.encode()).digest()[:16]
            iv = key
            counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            try:
                zip_data = cipher.decrypt_and_verify(enc_data, header)
            except ValueError:
                self.error.emit("Hibás jelszó vagy sérült fájl!")
                return
                
            # Kibontás ZIP in-memory tartalomból
            import io
            zipfile = ZipFile(io.BytesIO(zip_data))
            files = zipfile.infolist()
            for idx, member in enumerate(files):
                if not self._is_running:
                    self.stopped.emit()
                    return
                zipfile.extract(member, self.outdir)
                self.progress.emit(int((idx+1)/len(files)*100))
            self.finished.emit("Sikeres kibontás " + str(len(files)) + " fájl!")
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._is_running = False

class ModernApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modern 6zu AES Kibontó")
        self.setStyleSheet("""
            QWidget { background-color: #243043; color: #F0F3F7; border-radius: 10px; }
            QLabel { font-weight: bold; }
            QPushButton { background-color: #5E77FC; color: #fff; padding: 8px 24px; border: none; border-radius: 10px; font-weight: bold; }
            QPushButton:disabled { background-color: #777; color: #CCC; }
            QLineEdit { background-color: #222; color: #EEEEF1; border: 1px solid #5E77FC; border-radius: 6px; padding-left: 8px;}
            QProgressBar { border: 1px solid #5E77FC; border-radius: 6px; text-align: center; background: #222;}
            QProgressBar::chunk { background-color: #5E77FC; border-radius: 6px;}
        """)
        self.file_path = ''
        self.output_dir = ''
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        # Bemeneti fájl
        input_layout = QHBoxLayout()
        self.input_edit = QLineEdit(readOnly=True)
        browse_btn = QPushButton("Tallóz")
        browse_btn.clicked.connect(self.pick_file)
        input_layout.addWidget(QLabel("Bemeneti fájl:"))
        input_layout.addWidget(self.input_edit)
        input_layout.addWidget(browse_btn)
        layout.addLayout(input_layout)
        # Kimeneti mappa
        output_layout = QHBoxLayout()
        self.output_edit = QLineEdit(readOnly=True)
        output_btn = QPushButton("Kimeneti mappa")
        output_btn.clicked.connect(self.pick_output)
        output_layout.addWidget(QLabel("Kimeneti mappa:"))
        output_layout.addWidget(self.output_edit)
        output_layout.addWidget(output_btn)
        layout.addLayout(output_layout)
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        # Indít & Leállít
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Indít")
        self.start_btn.clicked.connect(self.run_action)
        self.stop_btn = QPushButton("Leállít")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_action)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        # Jelzés
        self.result_label = QLabel("")
        layout.addWidget(self.result_label)

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Válassz ki egy .6zu fájlt", "", "6zu Files (*.6zu)"
        )
        if path:
            self.file_path = path
            self.input_edit.setText(path)
            dir_path = os.path.dirname(path)
            self.output_dir = dir_path
            self.output_edit.setText(dir_path)

    def pick_output(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "Kimeneti mappa kiválasztása",
            self.output_dir if self.output_dir else ""
        )
        if dir_path:
            self.output_dir = dir_path
            self.output_edit.setText(dir_path)

    def run_action(self):
        if not self.file_path or not self.file_path.endswith('.6zu'):
            QMessageBox.warning(self, "Hiba", "Csak .6zu fájl választható ki!")
            return
        passwd, ok = QInputDialog.getText(self, "Jelszó szükséges", "Add meg a titkosításhoz használt jelszót!", echo=QLineEdit.EchoMode.Password)
        if not ok or not passwd:
            return
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.result_label.setText("Dekódolás és kibontás folyamatban...")
        self.worker = DecryptExtractThread(self.file_path, self.output_dir, passwd)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.handle_finished)
        self.worker.error.connect(self.handle_error)
        self.worker.stopped.connect(self.handle_stopped)
        self.worker.start()

    def stop_action(self):
        if self.worker:
            self.worker.stop()
            self.stop_btn.setEnabled(False)

    def handle_finished(self, msg):
        self.result_label.setText(msg)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def handle_error(self, msg):
        self.result_label.setText("Hiba: " + msg)
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def handle_stopped(self):
        self.result_label.setText("A feldolgozás megszakítva.")
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ModernApp()
    win.resize(650, 230)
    win.show()
    sys.exit(app.exec())
