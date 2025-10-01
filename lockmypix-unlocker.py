import sys
import os
import io
from zipfile import ZipFile
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QLineEdit, QProgressBar, QInputDialog, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES

class DecryptThread(QThread):
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
            with open(self.infile, "rb") as f:
                f.seek(0)
                header = f.read(64)  # előre elvárt fejlécek méret, igény szerint módosítható
                # Github kód alapján itt a fájl részletek:
                # 32 byte scrypt só (itt felteszem az első 32 bájt)
                salt = header[:32]
                # 12 byte nonce (32-44)
                nonce = header[32:44]
                # 16 byte tag (44-60)
                tag = header[44:60]
                # maradék titkosított adat
                f.seek(60)
                ciphertext = f.read()
            key = scrypt(self.password.encode('utf-8'), salt, 32, N=2**18, r=8, p=1)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            try:
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                self.error.emit("Hibás jelszó vagy sérült fájl!")
                return
            
            zipfile = ZipFile(io.BytesIO(decrypted))
            filelist = zipfile.infolist()
            for idx, member in enumerate(filelist):
                if not self._is_running:
                    self.stopped.emit()
                    return
                zipfile.extract(member, self.outdir)
                perc = int((idx + 1) / len(filelist) * 100)
                self.progress.emit(perc)
            self.finished.emit(f"Sikeres kicsomagolás, {len(filelist)} fájl!")
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._is_running = False

class ModernApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modern 6zu AES Dekóder")
        self.setStyleSheet("""
            QWidget { background-color: #2c3e50; color: #ecf0f1; border-radius: 10px; font-family: Arial, sans-serif;}
            QLabel { font-weight: 600; }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: 600;
            }
            QPushButton:hover:!disabled {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #7f8c8d;
            }
            QLineEdit {
                background-color: #34495e;
                border-radius: 6px;
                padding: 6px 8px;
                border: 1px solid #2980b9;
                color: #ecf0f1;
            }
            QProgressBar {
                border: 1px solid #2980b9;
                border-radius: 6px;
                text-align: center;
                background-color: #34495e;
                color: #ecf0f1;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 6px;
            }
        """)
        self.file_path = ""
        self.output_dir = ""
        self.worker = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Fájl tallózó
        file_layout = QHBoxLayout()
        self.file_edit = QLineEdit(readOnly=True)
        browse_btn = QPushButton("Tallóz")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(QLabel("Bemeneti .6zu fájl:"))
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)

        # Kimeneti mappa választó
        output_layout = QHBoxLayout()
        self.output_edit = QLineEdit(readOnly=True)
        output_btn = QPushButton("Kimeneti mappa")
        output_btn.clicked.connect(self.browse_output)
        output_layout.addWidget(QLabel("Kimeneti mappa:"))
        output_layout.addWidget(self.output_edit)
        output_layout.addWidget(output_btn)
        layout.addLayout(output_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Indít és Leállít gombok
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Indít")
        self.start_btn.clicked.connect(self.start_decryption)
        self.stop_btn = QPushButton("Leállít")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_decryption)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

        # Visszajelzés
        self.message_label = QLabel("")
        layout.addWidget(self.message_label)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Fájl kiválasztása", "", "6zu fájlok (*.6zu)"
        )
        if path:
            self.file_path = path
            self.file_edit.setText(path)
            out_dir = os.path.dirname(path)
            self.output_dir = out_dir
            self.output_edit.setText(out_dir)

    def browse_output(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "Kimeneti mappa kiválasztása", self.output_dir or ""
        )
        if dir_path:
            self.output_dir = dir_path
            self.output_edit.setText(dir_path)

    def start_decryption(self):
        if not self.file_path.endswith(".6zu"):
            QMessageBox.warning(self, "Hiba", "Csak .6zu fájl választható ki!")
            return
        passwd, ok = QInputDialog.getText(self, "Jelszó kérés", "Add meg a titkosítási jelszót:", QLineEdit.EchoMode.Password)
        if not ok or not passwd:
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.message_label.setText("Dekódolás folyamatban...")
        self.progress_bar.setValue(0)

        self.worker = DecryptThread(self.file_path, self.output_dir, passwd)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.decryption_finished)
        self.worker.error.connect(self.decryption_error)
        self.worker.stopped.connect(self.decryption_stopped)
        self.worker.start()

    def stop_decryption(self):
        if self.worker:
            self.worker.stop()
            self.stop_btn.setEnabled(False)
            self.message_label.setText("Dekódolás megszakítása folyamatban...")

    def decryption_finished(self, message):
        self.message_label.setText(message)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def decryption_error(self, message):
        self.message_label.setText("Hiba: " + message)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(0)

    def decryption_stopped(self):
        self.message_label.setText("A művelet megszakítva.")
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModernApp()
    window.resize(700, 220)
    window.show()
    sys.exit(app.exec())