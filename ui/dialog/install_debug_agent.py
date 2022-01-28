import os
import time
import ida_diskio
import ida_kernwin

from PyQt5.QtWidgets import *

from ekko.ui.utils import *
from ekko.store.profile import *
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
    DEFAULT_LABEL_WIDTH = 130
    DEFAULT_LINE_EDIT_WIDTH = 150

    def __init__(self, parent, vm_name):
        super().__init__(parent)
        self.parent = parent
        self.vm_name = vm_name
        self.qemu = QEMU.create_instance(vm_name)

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
        self.combo_box_os_type.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        # Label for installation steps
        self.label_install_step_title = QLabel("Installation steps")
        self.label_install_step_title.setStyleSheet("font-weight: bold; text-decoration: underline")
        self.label_install_step = QLabel(INSTALLATION_STEPS[OS_TYPES[0]])
    
    def _setup_layout(self):
        vbox = make_vbox(
            make_hbox(
                ("Guest OS type:", self.DEFAULT_LABEL_WIDTH),
                self.combo_box_os_type,
                align_left=True
            ),
            self.label_install_step_title,
            self.label_install_step,
            make_hbox(self.label_error, self.btn_install)
        )

        self.setLayout(vbox)

    def btn_install_clicked(self):
        if not self.qemu.is_qemu_started():
            ida_kernwin.warning("Please start VM first!")
            return

        os_type = self.combo_box_os_type.currentText()
        _, err = self.qemu.inject_cdrom(ISO_FILE_PATH[os_type])

        if err:
            self.label_error.setText(err)
            return
        
        self.qemu.stop_debug_agent()
        if self.qemu.wait_debug_agent_connection():
            self.close()

    def btn_cancle_clicked(self):
        self.close()
    
    def combo_box_os_type_changed(self, os_type):
        self.label_install_step.setText(INSTALLATION_STEPS[os_type])
