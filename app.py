import sys
import os
import time
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QLineEdit, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class WorkerThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    stopped = pyqtSignal()
    
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self._is_running = True

    def run(self):
        for i in range(101):
            if not self._is_running:
                self.stopped.emit()
                return
            time.sleep(0.04)  # szimulált feldolgozás
            self.progress.emit(i)
        self.finished.emit()

    def stop(self):
        self._is_running = False


class ModernApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Modern 6zu Fájl Feldolgozó")
        
        self.setStyleSheet("""
            QWidget {
                background-color: #343744;
                color: #EEEEF1;
                font-size: 14px;
                border-radius: 12px;
            }
            QPushButton {
                background-color: #5E77FC;
                color: #fff;
                padding: 8px 24px;
                border: none;
                border-radius: 10px;
                font-weight: bold;
            }
            QPushButton:disabled {
                background-color: #777;
                color: #CCC;
            }
            QLineEdit {
                background-color: #222;
                color: #EEEEF1;
                border: 1px solid #5E77FC;
                border-radius: 6px;
                padding-left: 8px;
            }
            QLabel {
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #5E77FC;
                border-radius: 6px;
                text-align: center;
                background: #222;
            }
            QProgressBar::chunk {
                background-color: #5E77FC;
                width: 10px;
                border-radius: 6px;
            }
        """)

        self.file_path = ''
        self.output_dir = ''
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

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

        # ProgressBar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Indít/Leállít gombok
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Indít")
        self.start_btn.clicked.connect(self.run_action)
        self.stop_btn = QPushButton("Leállít")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_action)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

        # Kimenet
        self.result_label = QLabel("")
        layout.addWidget(self.result_label)

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Válassz .6zu fájlt", "",
            "6zu Files (*.6zu)"
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
            self.result_label.setText("Csak .6zu fájl választható ki!")
            return
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.result_label.setText("Feldolgozás folyamatban...")
        self.worker = WorkerThread(self.file_path)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.handle_finished)
        self.worker.stopped.connect(self.handle_stopped)
        self.worker.start()

    def stop_action(self):
        if self.worker:
            self.worker.stop()
            self.stop_btn.setEnabled(False)

    def handle_finished(self):
        self.result_label.setText("Sikeres feldolgozás: " + os.path.basename(self.file_path))
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
    win.resize(640, 210)
    win.show()
    sys.exit(app.exec())
