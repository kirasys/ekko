import os
import logging

from PyQt5.QtWidgets import *
from PyQt5.QtGui import QFont
from ekko.ui.utils import *
from ekko.store.profile import ProfileStore

class DebugOutputView(QWidget):
    def __init__(self, vm_name):
        super().__init__()
        self.vm_name = vm_name
        self.logger = logging.getLogger(f"{vm_name}_debug_output")
        self.logger.setLevel(logging.DEBUG)

        self._add_log_handlers()
        self._setup_layout()
            
    def _add_log_handlers(self):
        self.text_log_handler = DebuggingLogHandler(self)
        self.logger.addHandler(self.text_log_handler)

        # Add a file handler
        profile = ProfileStore.get_vm_profile(self.vm_name)

        if profile.log_file is not None:
            log_path = os.path.join(profile.work_dir, f"debug_output.txt")
            file_log_handler = logging.FileHandler(log_path)
            self.logger.addHandler(file_log_handler)
        
    def _setup_layout(self):
        main_layout = make_vbox(
            self.text_log_handler.widget
        )
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(main_layout)

    def clear_output(self):
        self.text_log_handler.clear_log()

        # Clear a log file
        #profile = ProfileStore.get_vm_profile(self.vm_name)
        #open(os.path.join(profile.work_dir, profile.log_file), 'w').close()

class DebuggingLogHandler(logging.Handler):
    MAX_LOG_TEXT_LENGTH = 5000000 # 5MB

    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.widget = QPlainTextEdit(parent)
        self.widget.setFont(QFont('Consolas', 10))
        self.widget.setReadOnly(True)

    def emit(self, record):
        if len(self.widget.toPlainText()) > self.MAX_LOG_TEXT_LENGTH:
            self.parent.clear_log()

        msg = self.format(record)
        self.widget.insertPlainText(msg)
    
    def read_log(self, log_path):
        self.clear_log()

        with open(log_path, 'r') as f:
            text = f.read()

        self.widget.insertPlainText(text)

    def clear_log(self):
        self.widget.clear()