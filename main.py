# main.py
import sys
import time
from pathlib import Path
from PyQt5 import QtWidgets, QtGui, QtCore
from extractor import extract_artifacts


class WorkerSignals(QtCore.QObject):
    log = QtCore.pyqtSignal(str)
    progress = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(bool)


class Worker(QtCore.QRunnable):
    def __init__(self, image_path, output_root, signals):
        super().__init__()
        self.image_path = image_path
        self.output_root = output_root
        self.signals = signals

    def run(self):
        try:
            def log_cb(msg):
                self.signals.log.emit(msg)

            def progress_cb(msg):
                self.signals.progress.emit(msg)

            ok = extract_artifacts(
                self.image_path,
                self.output_root,
                progress_callback=progress_cb,
                log_callback=log_cb
            )
            self.signals.finished.emit(ok)

        except Exception as e:
            import traceback
            self.signals.log.emit(f"[ERROR] {e}")
            self.signals.log.emit(traceback.format_exc())
            self.signals.finished.emit(False)


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Forensics Artifact Extractor (Linux)")
        self.setMinimumSize(750, 450)

        layout = QtWidgets.QVBoxLayout()

        # -----------------------------
        # Image file selection row
        # -----------------------------
        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel("Image File:"))

        self.image_edit = QtWidgets.QLineEdit()
        self.image_edit.setReadOnly(True)
        row.addWidget(self.image_edit)

        self.btn_select = QtWidgets.QPushButton("Browse")
        self.btn_select.clicked.connect(self.select_image)
        row.addWidget(self.btn_select)

        layout.addLayout(row)

        # -----------------------------
        # Start button
        # -----------------------------
        self.btn_start = QtWidgets.QPushButton("Start Extraction")
        self.btn_start.setEnabled(False)
        self.btn_start.clicked.connect(self.start_extraction)
        layout.addWidget(self.btn_start)

        # -----------------------------
        # Progress bar
        # -----------------------------
        self.progress = QtWidgets.QProgressBar()
        self.progress.setVisible(False)
        self.progress.setRange(0, 0)  # indefinite
        layout.addWidget(self.progress)

        # -----------------------------
        # Log output
        # -----------------------------
        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        self.setLayout(layout)

        # Thread pool
        self.threadpool = QtCore.QThreadPool()

        # Worker signals
        self.signals = WorkerSignals()
        self.signals.log.connect(self.log_message)
        self.signals.progress.connect(self.log_message)
        self.signals.finished.connect(self.on_finished)

    # ---------------------------------------------------------
    # Logging helper
    # ---------------------------------------------------------
    def log_message(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log.append(f"[{ts}] {msg}")

    # ---------------------------------------------------------
    # Select E01 file
    # ---------------------------------------------------------
    def select_image(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            "/",
            "EWF Images (*.E01 *.e01 *.EWF *.ewf);;All Files (*)"
        )
        if fname:
            self.image_edit.setText(fname)
            self.btn_start.setEnabled(True)

    # ---------------------------------------------------------
    # Start extraction
    # ---------------------------------------------------------
    def start_extraction(self):
        image_path = self.image_edit.text().strip()
        if not image_path:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select an image file.")
            return

        img_path = Path(image_path)
        if not img_path.exists():
            QtWidgets.QMessageBox.warning(self, "Error", "Selected file does not exist.")
            return

        # Create output folder next to the image
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_root = img_path.parent / f"{img_path.stem}_artifacts_{timestamp}"
        output_root.mkdir(parents=True, exist_ok=True)

        self.log_message(f"Output folder: {output_root}")

        # Lock UI
        self.btn_start.setEnabled(False)
        self.btn_select.setEnabled(False)
        self.progress.setVisible(True)

        worker = Worker(str(image_path), str(output_root), self.signals)
        self.threadpool.start(worker)

    # ---------------------------------------------------------
    # Worker finished
    # ---------------------------------------------------------
    def on_finished(self, success):
        self.progress.setVisible(False)
        self.btn_start.setEnabled(True)
        self.btn_select.setEnabled(True)

        if success:
            self.log_message("Extraction completed successfully.")
            QtWidgets.QMessageBox.information(self, "Done", "Artifacts extracted successfully.")
        else:
            self.log_message("Extraction failed — check log output.")
            QtWidgets.QMessageBox.warning(self, "Error", "Extraction failed.")


# ---------------------------------------------------------
# Run application
# ---------------------------------------------------------
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
