import os

from PyQt5.QtWidgets import *

from ekko.ui.utils import *
from ekko.store.profile import ProfileStore
from ekko.ui.widget.vm_log_view import LoggingView

class VMLogWidget(QWidget):
    DEFAULT_LABEL_WIDTH = 100
    
    def __init__(self, parent, vm_name):
        super().__init__(parent)
        self.parent = parent
        self.vm_name = vm_name

        self._create_widget()
        self._setup_layout()
        self._load_profile()

    def _create_widget(self):
        # Group box
        self.group_config = QGroupBox("Configuration")
        self.group_output = QGroupBox("Output")

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
        
        # Log view widget
        self.widget_log_view = LoggingView(self.vm_name)
    
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
            self.widget_log_view
        )
        vbox.setContentsMargins(0, 0, 0, 0)
        self.group_output.setLayout(vbox)

        # main layout
        hbox = make_hbox(
            make_vbox(
                self.group_config, 
                self.btn_clear
            ),
            self.group_output
        )
        self.setLayout(hbox)
    
    def _load_profile(self):
        profile = ProfileStore.get_vm_profile(self.vm_name)

        if profile.log_file is not None:
            self.label_log_path.setText(f"$WORK_DIR\\{os.path.basename(profile.log_file)}")

        if profile.log_level is None or profile.log_level == "Debug":
            self.btn_debug_level.setChecked(True)
        elif profile.log_level == "Info":
            self.btn_info_level.setChecked(True)
        elif profile.log_level == "Warning":
            self.btn_warning_level.setChecked(True)
        elif profile.log_level == "Error":
            self.btn_error_level.setChecked(True)

    def btn_clear_clicked(self):
        self.widget_log_view.clear_log()

    def btn_log_level_clicked(self):
        btn = self.sender()
        if btn.isChecked():
            self.label_log_level.setText(btn.text())

            # Update log level
            self.widget_log_view.set_log_level(btn.text())
            ProfileStore.update_vm_profile(self.vm_name, log_level=btn.text())