import os
import time
import ida_diskio
import ida_kernwin

from PyQt5.QtWidgets import *

from ekko.ui.utils import *
from ekko.profile import *
from ekko.qemu.qemu import QEMU

OS_TYPES = [
    "Ubuntu 64bit"
]

INSTALLATION_STEPS = {
    OS_TYPES[0] : 
        "1. Click install button to insert the installation CD-ROM\n"
        "2. sudo mount /dev/cdrom /dev/shm\n"
        "3. sudo /dev/shm/install.sh\n"
        "4. Debug agent will connect to the IDA"
}

ISO_DIR = os.path.join(ida_diskio.idadir(""), "plugins", "ekko", "iso")

ISO_FILE_PATH = {
    OS_TYPES[0] : os.path.join(ISO_DIR, 'agent_ubuntu64.iso')
}

class DebugAgentInstallDialog(QDialog):
    LABEL_DEFAULT_WIDTH = 130
    LINE_EDIT_DEFAULT_WIDTH = 150

    def __init__(self, parent, profile_name):
        super().__init__(parent)
        self.parent = parent
        self.profile_name = profile_name
        self.qemu = QEMU.create_instance(profile_name)

        # Setting window title
        self.setWindowTitle("Debug agent installation")

        self._create_widget()
        self._setup_layout()
    
    def _create_widget(self):
        ####### Main widgets #######
        # Install | Cancel button
        self.btn_install = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.btn_install.button(QDialogButtonBox.Ok).setText("Install")
        self.btn_install.accepted.connect(self.btn_install_clicked)
        self.btn_install.rejected.connect(self.btn_cancle_clicked)

        self.label_error = QLabel("")
        self.label_error.setStyleSheet("color: red; font-weight: bold;")

        # ComboBox for Guest OS type
        self.combo_box_os_type = QComboBox()
        self.combo_box_os_type.addItems(OS_TYPES)
        self.combo_box_os_type.currentTextChanged.connect(self.combo_box_os_type_changed)
        self.combo_box_os_type.setFixedWidth(self.LINE_EDIT_DEFAULT_WIDTH)

        # Label for installation steps
        self.label_install_step_title = QLabel("Installation steps")
        self.label_install_step_title.setStyleSheet("font-weight: bold; text-decoration: underline")
        self.label_install_step = QLabel(INSTALLATION_STEPS[OS_TYPES[0]])
    
    def _setup_layout(self):
        vbox = make_vbox(
            make_hbox(
                ("Guest OS type:", self.LABEL_DEFAULT_WIDTH),
                self.combo_box_os_type,
                align_left=True
            ),
            self.label_install_step_title,
            self.label_install_step,
            make_hbox(self.label_error, self.btn_install)
        )

        self.setLayout(vbox)

    def btn_install_clicked(self):
        os_type = self.combo_box_os_type.currentText()
        success, error = self.qemu.inject_cdrom(ISO_FILE_PATH[os_type])

        if not success:
            self.label_error.setText(error)
            return

        ida_kernwin.show_wait_box("Wait for debug agent connection...")
        try:
            while True:
                time.sleep(0.5)
                if ida_kernwin.user_cancelled():
                    break
        finally:
            ida_kernwin.hide_wait_box()

    def btn_cancle_clicked(self):
        self.close()
    
    def combo_box_os_type_changed(self, os_type):
        self.label_install_step.setText(INSTALLATION_STEPS[os_type])
