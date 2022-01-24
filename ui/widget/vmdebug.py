import ida_nalt

from json.tool import main
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from ekko.ui.utils import *
from ekko.profile import *
from ekko.qemu.qemu import QEMU

class VMDebugWidget(QWidget):
    LABEL_DEFAULT_WIDTH = 180
    LINE_EDIT_WIDTH = 300
    BUTTON_INSTALL_WIDTH = 80
    BUTTON_UPLOAD_WIDTH = 60

    def __init__(self, parent, profile_name):
        super().__init__(parent)
        self.parent = parent
        self.profile_name = profile_name
        self.qemu = QEMU.create_instance(profile_name)

        self._create_widget()
        self._setup_layout()
        self._reload_layout()

    def _create_widget(self):
        # Button
        self.btn_install = QPushButton("Install")
        self.btn_install.setFixedWidth(self.BUTTON_INSTALL_WIDTH)
        self.btn_install.clicked.connect(self.btn_install_clicked)

        self.btn_reconnect = QPushButton("Reconnect")
        self.btn_reconnect.setFixedWidth(self.BUTTON_INSTALL_WIDTH)
        self.btn_reconnect.clicked.connect(self.btn_reconnect_clicked)

        self.btn_upload_app = QPushButton("Upload")
        self.btn_upload_app.setFixedWidth(self.BUTTON_UPLOAD_WIDTH)
        self.btn_upload_app.clicked.connect(self.btn_upload_app_clicked)

        self.btn_upload_lib = QPushButton("Upload")
        self.btn_upload_lib.setFixedWidth(self.BUTTON_UPLOAD_WIDTH)
        self.btn_upload_lib.clicked.connect(self.btn_upload_lib_clicked)
        
        # Label
        self.debug_agent_status_label = QLabel("Debug agent must be installed for debugging.")
        self.debug_agent_status_label.setStyleSheet("font-weight: bold; text-decoration: underline")
        
        # Group box
        self.group_debug_agent = QGroupBox("Debug agent")
        self.group_config = QGroupBox("Configuration")

        # Text box
        self.box_debug_dest_path = QLineEdit('/root')
        self.box_debug_dest_path.setFixedWidth(self.LINE_EDIT_WIDTH)

        self.box_app_path = QLineEdit(get_input_file_path())
        self.box_app_path.setFixedWidth(self.LINE_EDIT_WIDTH)

        self.box_lib_path = QLineEdit('')
        self.box_lib_path.setFixedWidth(self.LINE_EDIT_WIDTH)
    
    def _setup_layout(self):
        # config layout
        vbox = make_vbox(
            make_hbox(
                ("Debugging destination directory", self.LABEL_DEFAULT_WIDTH), ": ",
                self.box_debug_dest_path,
                align_left=True,
            ),
            make_hbox(
                ("Application binary", self.LABEL_DEFAULT_WIDTH), ": ",
                self.box_app_path, self.btn_upload_app,
                align_left=True,
            ),
            make_hbox(
                ("Libirary files (optional)", self.LABEL_DEFAULT_WIDTH), ": ",
                self.box_lib_path, self.btn_upload_lib,
                align_left=True,
            )
        )
        self.group_config.setLayout(vbox)

        # main layout
        main_layout = make_vbox(
            ("Warning: All debugging-related operations are executed as root."),
            make_hbox(
                self.debug_agent_status_label,
                self.btn_install, self.btn_reconnect,
                align_left=True,
            ),
            self.group_config,
        )

        self.setLayout(main_layout)
    
    def _reload_layout(self):
        if not self.qemu.is_agent_connected():
            # Update the status label
            self.debug_agent_status_label.setText("Debug agent is connected!")

            # Change the install button text.
            self.btn_install.setText("Reinstall")

            # Show other widgets
            self.group_config.show()
        else:
            # Update the status label
            self.debug_agent_status_label.setText("Debug agent must be installed for debugging.")

            # Change the install button text.
            self.btn_install.setText("Install")

            # Hide other widgets
            self.group_config.hide()
    
    def btn_install_clicked(self):
        from ekko.ui.dialog.agent_install import DebugAgentInstallDialog
        dialog = DebugAgentInstallDialog(self.parent, self.profile_name)
        dialog.exec_()
    
    def btn_reconnect_clicked(self):
        self._reload_layout()
    
    def btn_upload_app_clicked(self):
        pass

    def btn_upload_lib_clicked(self):
        pass

def get_input_file_path():
    input_file = ida_nalt.get_input_file_path()
    
    # WSL issue?
    if input_file.startswith('/mnt/'):
        drive = input_file[5].upper()
        input_file = f"{drive}:{input_file[6:]}"

    return input_file