import os
import logging

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *
from ekko.ui.utils import *
from ekko.profile import *

class QemuLogWidget(QWidget):
    LABEL_DEFAULT_WIDTH = 100

    def __init__(self, parent, profile_name):
        super(QemuLogWidget, self).__init__()
        self.parent = parent
        self.profile_name = profile_name

        self._create_widget()
        self._setup_layout()
        self._load_profile()

    def _create_widget(self):
        # Group box
        self.group_config = QGroupBox("Configuration")
        self.group_qemu_log = QGroupBox("Output")

        # Clear button
        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.btn_clear_clicked)

        # Log path label
        self.label_log_path = QLabel("")

        # Log level button
        self.label_log_level = QLabel("")

        self.btn_debug_level = QRadioButton('Debug')
        self.btn_debug_level.toggled.connect(self.btn_log_level_clicked)

        self.btn_info_level = QRadioButton('Info')
        self.btn_info_level.toggled.connect(self.btn_log_level_clicked)

        self.btn_warning_level = QRadioButton('Warning')
        self.btn_warning_level.toggled.connect(self.btn_log_level_clicked)

        self.btn_error_level = QRadioButton('Error')
        self.btn_error_level.toggled.connect(self.btn_log_level_clicked)
        
        self.dialog_logging = DialogLogger(self.profile_name)
    
    def _setup_layout(self):
        # Configuration layout
        vbox = make_vbox(
            make_hbox("Log path :", self.label_log_path),
            "Log level : ",
            make_vbox(
                self.btn_debug_level,
                self.btn_info_level,
                self.btn_warning_level,
                self.btn_error_level
            ),
        )
        self.group_config.setLayout(vbox)

        # QEMU Logging layout
        vbox = make_vbox(
            self.dialog_logging
        )
        vbox.setContentsMargins(0, 0, 0, 0)
        self.group_qemu_log.setLayout(vbox)

        # main layout
        hbox = make_hbox(
            make_vbox(
                self.group_config, 
                self.btn_clear
            ),
            self.group_qemu_log
        )
        self.setLayout(hbox)
    
    def _load_profile(self):
        profile = get_vm_profile(self.profile_name)

        if profile.log_file is not None:
            self.label_log_path.setText(f"$WORK_DIR\\{profile.log_file}")

        if profile.log_level is None or profile.log_level == "Debug":
            self.btn_debug_level.setChecked(True)
        elif profile.log_level == "Info":
            self.btn_info_level.setChecked(True)
        elif profile.log_level == "Warning":
            self.btn_warning_level.setChecked(True)
        elif profile.log_level == "Error":
            self.btn_error_level.setChecked(True)

    def btn_clear_clicked(self):
        self.dialog_logging.clear_log()

    def btn_log_level_clicked(self):
        btn = self.sender()
        if btn.isChecked():
            self.label_log_level.setText(btn.text())

            # Update log level
            if get_vm_profile(self.profile_name).log_level != btn.text():
                self.dialog_logging.set_log_level(btn.text())

            update_vm_profile(self.profile_name, log_level=btn.text())
    
class QTextEditLogger(logging.Handler):
    MAX_LOG_TEXT_LENGTH = 3000000 # 3MB

    def __init__(self, parent):
        super(QTextEditLogger, self).__init__()
        self.parent = parent
        self.widget = QPlainTextEdit(parent)
        self.widget.setReadOnly(True)

    def emit(self, record):
        if len(self.widget.toPlainText()) > self.MAX_LOG_TEXT_LENGTH:
            self.parent.clear_log()

        msg = self.format(record)
        self.widget.appendPlainText(msg)
    
    def set_log(self, text):
        self.widget.setPlainText(text)

    def clear_log(self):
        self.widget.clear()

class DialogLogger(QDialog, QPlainTextEdit):
    def __init__(self, profile_name):
        super(DialogLogger, self).__init__()
        self.profile_name = profile_name

        self.log_text_box = QTextEditLogger(self)
        self.log_text_box.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S'))
        logging.getLogger().addHandler(self.log_text_box)

        # Add a file handler
        profile = get_vm_profile(profile_name)

        if profile.log_file is not None:
            log_path = os.path.join(profile.work_dir, profile.log_file)
            file_handler = logging.FileHandler(log_path)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S'))
            logging.getLogger().addHandler(file_handler)
        
            # Read a log file
            with open(log_path, 'r') as f:
                self.log_text_box.set_log(f.read().strip())

        main_layout = make_vbox(
            self.log_text_box.widget
        )
        
        self.setLayout(main_layout)
    
    def clear_log(self):
        self.log_text_box.clear_log()

        # Clear a log file
        profile = get_vm_profile(self.profile_name)
        open(os.path.join(profile.work_dir, profile.log_file), 'w').close()
    
    def set_log_level(self, level):
        if level == "Debug":
            logging.getLogger().setLevel(logging.DEBUG)
        elif level == "Info":
            logging.getLogger().setLevel(logging.INFO)
        elif level == "Warning":
            logging.getLogger().setLevel(logging.WARNING)
        elif level == "ERROR":
            logging.getLogger().setLevel(logging.ERROR)
        
        logging.info(f"Change the log level to {level.upper()}")