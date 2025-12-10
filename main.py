#!/usr/bin/env python3

import sys
import time
from pathlib import Path
from collections import deque

from PyQt5 import QtWidgets, QtGui, QtCore

from extractor import extract_artifacts


# ---------- Worker & signals ----------
class WorkerSignals(QtCore.QObject):
    log = QtCore.pyqtSignal(str)         # message string
    progress = QtCore.pyqtSignal(str)    # progress text (still a string from extractor)
    finished = QtCore.pyqtSignal(bool)   # success flag


class Worker(QtCore.QRunnable):
    """Background worker that runs extract_artifacts in threadpool."""
    def __init__(self, image_path, output_root):
        super().__init__()
        self.image_path = image_path
        self.output_root = output_root
        self.signals = WorkerSignals()

    def run(self):
        try:
            def log_cb(msg):
                # forward logs
                self.signals.log.emit(str(msg))

            def progress_cb(msg):
                self.signals.progress.emit(str(msg))

            ok = extract_artifacts(
                self.image_path,
                self.output_root,
                progress_callback=progress_cb,
                log_callback=log_cb
            )
            self.signals.finished.emit(bool(ok))
        except Exception as e:
            import traceback
            self.signals.log.emit(f"[ERROR] {e}")
            self.signals.log.emit(traceback.format_exc())
            self.signals.finished.emit(False)


# ---------- Main GUI ----------
class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Forensics Artifact Extractor")
        self.setMinimumSize(900, 600)
        self.setWindowIcon(QtGui.QIcon())  # place if you have an icon

        # Styling (simple)
        self.setStyleSheet("""
        QWidget { font-family: Inter, Arial, sans-serif; font-size: 13px; }
        QGroupBox { font-weight: 600; border: 1px solid #ddd; border-radius: 6px; margin-top: 10px; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px 0 4px; }
        QPushButton { padding: 6px 12px; }
        QTextEdit { background: #0f0f0f; color: #e6e6e6; font-family: monospace; }
        """)

        # Layout
        main_layout = QtWidgets.QVBoxLayout(self)
        header = self._build_header()
        main_layout.addWidget(header)

        control_box = self._build_controls()
        main_layout.addWidget(control_box)

        status_box = self._build_status()
        main_layout.addWidget(status_box)

        log_box = self._build_log()
        main_layout.addWidget(log_box, stretch=1)

        self.setLayout(main_layout)

        # Thread pool
        self.threadpool = QtCore.QThreadPool.globalInstance()

        # Worker bookkeeping
        self.worker = None
        self.worker_signals = None

        # Timer for elapsed/ETA
        self._start_time = None
        self._timer = QtCore.QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._on_timer_tick)

        # Processed item counting (we sniff "[SAVED]" in logs)
        self.processed_count = 0
        self.expected_count = 0  # user-provided
        self.recent_intervals = deque(maxlen=64)  # for moving average

    # ---------------- UI parts ----------------
    def _build_header(self):
        w = QtWidgets.QWidget()
        h = QtWidgets.QHBoxLayout(w)
        title = QtWidgets.QLabel("<h2>Windows Forensics Artifact Extractor</h2>")
        subtitle = QtWidgets.QLabel("Open E01 images and extract Windows artifacts (Prefetch, Registry, Browser, $MFT, $J, ...)")
        subtitle.setStyleSheet("color: #666;")
        left = QtWidgets.QVBoxLayout()
        left.addWidget(title)
        left.addWidget(subtitle)
        h.addLayout(left)

        # right side: simple status badge
        self.status_badge = QtWidgets.QLabel("Idle")
        self.status_badge.setAlignment(QtCore.Qt.AlignCenter)
        self.status_badge.setFixedWidth(120)
        self.status_badge.setStyleSheet("background:#f0f0f0;border-radius:6px;padding:6px;")
        h.addStretch()
        h.addWidget(self.status_badge)
        return w

    def _build_controls(self):
        g = QtWidgets.QGroupBox("Controls")
        layout = QtWidgets.QGridLayout()

        # Image selection
        layout.addWidget(QtWidgets.QLabel("Image File:"), 0, 0)
        self.image_edit = QtWidgets.QLineEdit()
        self.image_edit.setReadOnly(True)
        layout.addWidget(self.image_edit, 0, 1)
        self.btn_select = QtWidgets.QPushButton("Browse...")
        self.btn_select.clicked.connect(self.select_image)
        layout.addWidget(self.btn_select, 0, 2)

        # Expected items (optional) for ETA/progress
        layout.addWidget(QtWidgets.QLabel("Expected items (optional):"), 1, 0)
        self.spin_expected = QtWidgets.QSpinBox()
        self.spin_expected.setRange(0, 1000000)
        self.spin_expected.setValue(0)
        self.spin_expected.setToolTip("Set an approximate number of artifacts/files expected to be extracted. Used to compute an ETA.")
        self.spin_expected.valueChanged.connect(self._on_expected_changed)
        layout.addWidget(self.spin_expected, 1, 1)

        # Output location label
        layout.addWidget(QtWidgets.QLabel("Output folder:"), 2, 0)
        self.out_edit = QtWidgets.QLineEdit()
        self.out_edit.setReadOnly(True)
        layout.addWidget(self.out_edit, 2, 1)
        self.btn_choose_out = QtWidgets.QPushButton("Choose...")
        self.btn_choose_out.clicked.connect(self.select_output_folder)
        layout.addWidget(self.btn_choose_out, 2, 2)

        # Buttons row
        btn_row = QtWidgets.QHBoxLayout()
        self.btn_start = QtWidgets.QPushButton("Start Extraction")
        self.btn_start.setEnabled(False)
        self.btn_start.clicked.connect(self.start_extraction)
        btn_row.addWidget(self.btn_start)

        self.btn_clear_log = QtWidgets.QPushButton("Clear Log")
        self.btn_clear_log.clicked.connect(self.clear_log)
        btn_row.addWidget(self.btn_clear_log)

        self.btn_copy_log = QtWidgets.QPushButton("Copy Log")
        self.btn_copy_log.clicked.connect(self.copy_log)
        btn_row.addWidget(self.btn_copy_log)

        self.btn_open_out = QtWidgets.QPushButton("Open Output")
        self.btn_open_out.clicked.connect(self.open_output_folder)
        btn_row.addWidget(self.btn_open_out)

        # Add row to layout
        layout.addLayout(btn_row, 3, 0, 1, 3)

        g.setLayout(layout)
        return g

    def _build_status(self):
        g = QtWidgets.QGroupBox("Status")
        layout = QtWidgets.QHBoxLayout()

        # Progress bar (determinate if expected_count set)
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar, stretch=3)

        # Stats panel
        stats_layout = QtWidgets.QFormLayout()
        self.lbl_elapsed = QtWidgets.QLabel("00:00:00")
        self.lbl_eta = QtWidgets.QLabel("—")
        self.lbl_counts = QtWidgets.QLabel("0 / 0")
        stats_layout.addRow("Elapsed:", self.lbl_elapsed)
        stats_layout.addRow("ETA:", self.lbl_eta)
        stats_layout.addRow("Processed:", self.lbl_counts)
        layout.addLayout(stats_layout, stretch=1)

        g.setLayout(layout)
        return g

    def _build_log(self):
        g = QtWidgets.QGroupBox("Log")
        v = QtWidgets.QVBoxLayout()
        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        self.log.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        font = QtGui.QFont("Courier New")
        font.setPointSize(10)
        self.log.setFont(font)
        v.addWidget(self.log)
        g.setLayout(v)
        return g

    # ---------------- UI actions ----------------
    def select_image(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            str(Path.home()),
            "EWF Images (*.E01 *.e01 *.EWF *.ewf);;All Files (*)"
        )
        if not fname:
            return
        self.image_edit.setText(fname)
        # set default output folder next to image
        img_path = Path(fname)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        default_out = img_path.parent / f"{img_path.stem}_artifacts_{timestamp}"
        self.out_edit.setText(str(default_out))
        self.btn_start.setEnabled(True)

    def select_output_folder(self):
        fd = QtWidgets.QFileDialog.getExistingDirectory(self, "Select output folder", str(Path.home()))
        if fd:
            self.out_edit.setText(fd)

    def open_output_folder(self):
        out = self.out_edit.text().strip()
        if not out:
            QtWidgets.QMessageBox.information(self, "Open Output", "No output folder set.")
            return
        p = Path(out)
        if not p.exists():
            QtWidgets.QMessageBox.warning(self, "Open Output", "Output folder does not exist.")
            return
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(p)))

    def clear_log(self):
        self.log.clear()

    def copy_log(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(self.log.toPlainText())
        QtWidgets.QMessageBox.information(self, "Copied", "Log copied to clipboard.")

    # ---------------- Extraction lifecycle ----------------
    def start_extraction(self):
        image_path = self.image_edit.text().strip()
        out_path = self.out_edit.text().strip()
        if not image_path:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select an image file.")
            return
        if not out_path:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select or confirm an output folder.")
            return

        img_path = Path(image_path)
        if not img_path.exists():
            QtWidgets.QMessageBox.warning(self, "Error", "Selected image file does not exist.")
            return

        out_root = Path(out_path)
        out_root.mkdir(parents=True, exist_ok=True)

        # start timer + counters
        self._start_time = time.time()
        self._timer.start()
        self.processed_count = 0
        self.expected_count = int(self.spin_expected.value())
        self.recent_intervals.clear()
        self._update_status_labels()

        # update UI state
        self.status_badge.setText("Running")
        self.status_badge.setStyleSheet("background:#d0f0d0;border-radius:6px;padding:6px;color:#0a0;")
        self.btn_start.setEnabled(False)
        self.btn_select.setEnabled(False)
        self.btn_choose_out.setEnabled(False)
        self.spin_expected.setEnabled(False)
        self.btn_open_out.setEnabled(False)

        # prepare worker
        worker = Worker(image_path, str(out_root))
        self.worker = worker
        signals = worker.signals
        signals.log.connect(self._on_log)
        signals.progress.connect(self._on_progress_text)
        signals.finished.connect(self._on_finished)

        # kick off
        self.threadpool.start(worker)
        self.log_message("Extraction started.")
        self.progress_bar.setValue(0)
        if self.expected_count > 0:
            self.progress_bar.setRange(0, self.expected_count)
            self.progress_bar.setFormat("%v / %m")
        else:
            # indeterminate style by animating between 0 and 100
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setFormat("Running (items counted: %v)")

    def _on_log(self, msg):
        # general log handler
        self.log_message(msg)

        # inspect saved events for counting
        if isinstance(msg, str):
            lower = msg.lower()
            if "[saved]" in lower or "[saved]" in msg or "saved ->" in lower or "[s1AVED]" in msg:
                # count saved artifact
                self._increment_processed()

    def _on_progress_text(self, msg):
        # progress callback from extractor (also shown as logs)
        self.log_message(f"[PROGRESS] {msg}")
        # some extractor progress messages may contain file names we can count
        lower = msg.lower()
        if "saved" in lower or "saved]" in lower or "saved ->" in lower:
            self._increment_processed()

    def _increment_processed(self):
        self.processed_count += 1
        # update moving average of interval between processed items
        now = time.time()
        if hasattr(self, "_last_processed_time") and self._last_processed_time:
            dt = now - self._last_processed_time
            if dt > 0:
                self.recent_intervals.append(dt)
        self._last_processed_time = now
        self._update_progress_ui()

    def _update_progress_ui(self):
        # update labels and progress bar
        self._update_status_labels()
        if self.expected_count > 0:
            done = min(self.processed_count, self.expected_count)
            self.progress_bar.setValue(done)
        else:
            # animate progress to show activity - set value = processed_count modulo 100
            self.progress_bar.setValue(self.processed_count % 100)

    def _on_timer_tick(self):
        # update elapsed and ETA every second
        self._update_status_labels()

    def _update_status_labels(self):
        # elapsed
        if self._start_time:
            elapsed = int(time.time() - self._start_time)
        else:
            elapsed = 0
        self.lbl_elapsed.setText(self._format_seconds(elapsed))

        # processed / expected
        self.lbl_counts.setText(f"{self.processed_count} / {self.expected_count if self.expected_count>0 else '—'}")

        # ETA estimation: if expected_count known and processed_count>0 compute
        eta_text = "—"
        if self.expected_count > 0 and self.processed_count > 0:
            avg = None
            if len(self.recent_intervals) > 0:
                avg = sum(self.recent_intervals) / len(self.recent_intervals)
            else:
                # fallback to global average
                elapsed = max(1, int(time.time() - (self._start_time or time.time())))
                avg = elapsed / max(1, self.processed_count)
            remaining = max(0, self.expected_count - self.processed_count)
            eta_seconds = int(avg * remaining)
            eta_text = self._format_seconds(eta_seconds)
        elif self._start_time and self.processed_count > 0 and self.expected_count == 0:
            # unknown expected, show avg speed like "avg: 0.5s/item"
            if len(self.recent_intervals) > 0:
                avg = sum(self.recent_intervals) / len(self.recent_intervals)
                eta_text = f"avg {avg:.2f}s/item"
            else:
                eta_text = "avg ?"
        self.lbl_eta.setText(eta_text)

    def _on_finished(self, success):
        # stop timer
        self._timer.stop()
        self._start_time = None

        # re-enable UI
        self.btn_start.setEnabled(True)
        self.btn_select.setEnabled(True)
        self.btn_choose_out.setEnabled(True)
        self.spin_expected.setEnabled(True)
        self.btn_open_out.setEnabled(True)

        # final status
        if success:
            self.status_badge.setText("Idle")
            self.status_badge.setStyleSheet("background:#f0f0f0;border-radius:6px;padding:6px;")
            self.log_message("Extraction completed successfully.")
            QtWidgets.QMessageBox.information(self, "Done", "Artifacts extracted successfully.")
        else:
            self.status_badge.setText("Error")
            self.status_badge.setStyleSheet("background:#ffd6d6;border-radius:6px;padding:6px;color:#900;")
            self.log_message("Extraction failed — check log output.")
            QtWidgets.QMessageBox.warning(self, "Error", "Extraction failed. See log for details.")

    # ---------------- Log helpers ----------------
    def log_message(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log.append(f"[{ts}] {msg}")
        # autoscroll
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def copy_log(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(self.log.toPlainText())
        QtWidgets.QMessageBox.information(self, "Copied", "Log copied to clipboard.")

    # ---------------- misc ----------------
    def _format_seconds(self, s: int) -> str:
        h = s // 3600
        m = (s % 3600) // 60
        sec = s % 60
        return f"{h:02d}:{m:02d}:{sec:02d}"

    def _on_expected_changed(self, v):
        self.expected_count = int(v)
        if self.expected_count > 0:
            self.progress_bar.setRange(0, self.expected_count)
            self.progress_bar.setFormat("%v / %m")
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setFormat("Running (items counted: %v)")

    # connect progress handlers
    def _on_progress_text(self, msg):
        # treat same as a log but keep label
        self._on_log(msg)

    # tiny shortcut for clear log + reset counters
    def reset_counters(self):
        self.processed_count = 0
        self.expected_count = int(self.spin_expected.value())
        self.recent_intervals.clear()
        self._last_processed_time = None
        self._update_progress_ui()


# ---------- run ----------
def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
