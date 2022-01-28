import os
import logging

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *
from ekko.ui.utils import *
from ekko.store.profile import *

LOG_COLOR_TEMPLATE_MAP = {
    logging.DEBUG : '<div style="color:#303030; font-weight:bold">%s</div>',
    logging.INFO : '<div style="color:#3333FF; font-weight:bold">%s</div>',
    logging.WARNING : '<div style="color:#FF8000; font-weight:bold">%s</div>',
    logging.ERROR : '<div style="color:#FF3333; font-weight:bold">%s</div>'
}

class TextLogHandler(logging.Handler):
    MAX_LOG_TEXT_LENGTH = 3000000 # 3MB

    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.widget = QPlainTextEdit(parent)
        self.widget.setReadOnly(True)

    def format(self, record: logging.LogRecord):
        msg = super().format(record)
        return LOG_COLOR_TEMPLATE_MAP[record.levelno] % msg

    def emit(self, record):
        if len(self.widget.toPlainText()) > self.MAX_LOG_TEXT_LENGTH:
            self.parent.clear_log()

        msg = self.format(record)
        self.widget.appendHtml(msg)
    
    def read_log(self, log_path):
        self.clear_log()

        with open(log_path, 'r') as f:
            text = f.read().strip()

        # Color log by level
        text_by_lines = text.split('\n')
        for i in range(len(text_by_lines)):
            msg = text_by_lines[i]

            if '- DEBUG -' in msg:
                msg = LOG_COLOR_TEMPLATE_MAP[logging.DEBUG] % msg
            elif '- INFO -' in msg:
                msg = LOG_COLOR_TEMPLATE_MAP[logging.INFO] % msg
            elif '- WARNING -' in msg:
                msg = LOG_COLOR_TEMPLATE_MAP[logging.WARNING] % msg
            elif '- ERROR -' in msg:
                msg = LOG_COLOR_TEMPLATE_MAP[logging.ERROR] % msg
        
            text_by_lines[i] = msg

        self.widget.appendHtml(''.join(text_by_lines))

    def clear_log(self):
        self.widget.clear()

class LoggingView(QWidget):
    def __init__(self, vm_name):
        super().__init__()
        self.vm_name = vm_name
        self.logger = logging.getLogger(vm_name)
    
        self._add_log_handlers()
        self._setup_layout()

    def _add_log_handlers(self):
        log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')

        # Set plain log format
        self.text_log_handler = TextLogHandler(self)
        self.text_log_handler.setFormatter(log_format)
        self.logger.addHandler(self.text_log_handler)

        # Add a file handler
        profile = get_vm_profile(self.vm_name)

        if profile.log_file is not None:
            log_path = os.path.join(profile.work_dir, profile.log_file)
            file_log_handler = logging.FileHandler(log_path)
            file_log_handler.setFormatter(log_format)
            self.logger.addHandler(file_log_handler)
        
            # Read a log file
            self.text_log_handler.read_log(log_path)
    
    def _setup_layout(self):
        main_layout = make_vbox(
            self.text_log_handler.widget
        )
        
        self.setLayout(main_layout)

    def clear_log(self):
        self.text_log_handler.clear_log()

        # Clear a log file
        profile = get_vm_profile(self.vm_name)
        open(os.path.join(profile.work_dir, profile.log_file), 'w').close()
    
    def set_log_level(self, level):
        if level == "Debug":
            self.logger.setLevel(logging.DEBUG)
        elif level == "Info":
            self.logger.setLevel(logging.INFO)
        elif level == "Warning":
            self.logger.setLevel(logging.WARNING)
        elif level == "ERROR":
            self.logger.setLevel(logging.ERROR)