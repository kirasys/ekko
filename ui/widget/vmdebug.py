import os
import idaapi
import ida_dbg
import ida_nalt

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from ekko.utils import *
from ekko.ui.utils import *
from ekko.store.profile import ProfileStore
from ekko.qemu.qemu import QEMU

class VMDebugWidget(QWidget):
    DEFAULT_LABEL_WIDTH = 210
    DEFAULT_LINE_EDIT_WIDTH = 250
    XLARGE_BUTTON_WIDTH = 110
    LARGE_BUTTON_WIDTH = 80
    SMALL_BUTTON_WIDTH = 60

    def __init__(self, parent, vm_name):
        super().__init__(parent)
        self.parent = parent
        self.vm_name = vm_name
        self.qemu = QEMU.create_instance(vm_name)

        self._create_widget()
        self._setup_layout()
        self._reload_layout()

        self._load_debug_process_options()

    def _create_widget(self):
        # Button
        self.btn_install = QPushButton("Install")
        self.btn_install.setFixedWidth(self.LARGE_BUTTON_WIDTH)
        self.btn_install.clicked.connect(self.btn_install_clicked)

        self.btn_reconnect = QPushButton("Reconnect")
        self.btn_reconnect.setFixedWidth(self.LARGE_BUTTON_WIDTH)
        self.btn_reconnect.clicked.connect(self.btn_reconnect_clicked)

        self.btn_upload_app = QPushButton("Upload")
        self.btn_upload_app.setFixedWidth(self.SMALL_BUTTON_WIDTH)
        self.btn_upload_app.clicked.connect(self.btn_upload_app_clicked)

        self.btn_save_config = QPushButton("Save")
        self.btn_save_config.setFixedWidth(self.SMALL_BUTTON_WIDTH)
        self.btn_save_config.clicked.connect(self.btn_save_config_clicked)

        self.btn_restore_config = QPushButton("Restore")
        self.btn_restore_config.setFixedWidth(self.SMALL_BUTTON_WIDTH)
        self.btn_restore_config.clicked.connect(self.btn_restore_config_clicked)

        self.btn_quick_start = QPushButton("Quick launch")
        self.btn_quick_start.setFixedWidth(self.XLARGE_BUTTON_WIDTH)
        self.btn_quick_start.clicked.connect(self.btn_quick_start_clicked)

        self.btn_quick_attach = QPushButton("Quick attach")
        self.btn_quick_attach.setFixedWidth(self.XLARGE_BUTTON_WIDTH)
        self.btn_quick_attach.clicked.connect(self.btn_quick_attach_clicked)

        self.btn_interactive_shell = QPushButton("Interactive shell")
        self.btn_interactive_shell.setFixedWidth(self.XLARGE_BUTTON_WIDTH)
        self.btn_interactive_shell.clicked.connect(self.btn_interactive_shell_clicked)
        
        # Label
        self.debug_agent_status_label = QLabel("Debug agent must be installed for debugging.")
        self.debug_agent_status_label.setStyleSheet("font-weight: bold; text-decoration: underline")

        self.label_error = QLabel("")
        self.label_error.setStyleSheet("color: red; font-weight: bold;")
        
        # Group box
        self.group_config = QGroupBox("Configuration")
        self.group_advanced = QGroupBox("Advanced debugging")

        # Text box
        self.box_guest_app_path = QLineEdit('')
        self.box_guest_app_path.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_host_app_path = QLineEdit('')
        self.box_host_app_path.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_debug_app_parameter = QLineEdit('')
        self.box_debug_app_parameter.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_debug_dir = QLineEdit('')
        self.box_debug_dir.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)
    
    def _setup_layout(self):
        # config layout
        vbox = make_vbox(
            make_hbox(
                ("Application path in guest", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_guest_app_path,
                align_left=True,
            ),
            make_hbox(
                ("Application path in host (optional)", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_host_app_path, self.btn_upload_app,
                align_left=True,
            ),
            make_hbox(
                ("Parameters (optional)", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_debug_app_parameter,
                align_left=True,
            ),
            make_hbox(
                ("Debugging base directory (optional)", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_debug_dir,
                align_left=True,
            ),
            " ",
            make_hbox(self.btn_save_config, self.btn_restore_config, align_left=True),
        )
        self.group_config.setLayout(vbox)

        # Advanced layout
        vbox = make_vbox(
            make_hbox(
            self.btn_quick_start, ": Quickly start a new process via auto configuration"
            ),
            make_hbox(
                self.btn_quick_attach, ": Quickly attach the debugger via auto configuration"
            ),
            make_hbox(
                self.btn_interactive_shell, ": Open an interactive shell window to communicate with a process"
            ),
        )
        self.group_advanced.setLayout(vbox)

        # main layout
        main_layout = make_vbox(
            ("Warning: All debugging-related operations are executed as root."),
            make_hbox(
                self.debug_agent_status_label,
                self.btn_install, self.btn_reconnect,
                align_left=True,
            ),
            make_hbox(self.group_config, self.group_advanced, align_left=True),
            self.label_error,
        )

        self.setLayout(main_layout)

    def _reload_layout(self):
        if self.qemu.is_debug_agent_connectable():
            # Update the status label
            self.debug_agent_status_label.setText("Debug agent is connected!")

            # Change the install button text.
            self.btn_install.setText("Reinstall")

            # Show groups
            self.group_config.show()
            self.group_advanced.show()
            
            return True
        else:
            # Update the status label
            self.debug_agent_status_label.setText("Debug agent must be installed for debugging.")

            # Change the install button text.
            self.btn_install.setText("Install")

            # Hide groups
            self.group_config.hide()
            self.group_advanced.hide()

            return False
    
    def _load_debug_process_options(self):
        self.btn_restore_config_clicked()

        app_path, app_parameters, debug_dir, host, _, _ = ida_dbg.get_process_options()

        if host == "127.0.0.1": # is config already set
            self.box_guest_app_path.setText(app_path)
            self.box_debug_app_parameter.setText(app_parameters)
            self.box_debug_dir.setText(debug_dir)
            

    def btn_install_clicked(self):
        if not self.qemu.is_online():
            idaapi.warning("VM is offline")
            return

        from ekko.ui.dialog.install_debug_agent import DebugAgentInstallDialog
        dialog = DebugAgentInstallDialog(self.parent, self.vm_name)
        dialog.exec_()

        self._reload_layout()
    
    def btn_reconnect_clicked(self):
        if not self.qemu.is_online():
            idaapi.warning("VM is offline")
            return

        self.qemu.wait_debug_agent_connection()
        self._reload_layout()
    
    def btn_interactive_shell_clicked(self):
        from ekko.ui.tab.interactive_debug_shell import InteractiveDebugShell
        debug_shell = InteractiveDebugShell(self.vm_name)
        debug_shell.Show()

    def _validate_input(self):
        if self.box_guest_app_path.text() == "":
            idaapi.warning("Please enter an apllication path (guest)")
            return False
        
        return True

    def btn_upload_app_clicked(self):
        if self._validate_input() and self._reload_layout():
            host_app_path = self.box_host_app_path.text()
            guest_app_path = self.box_guest_app_path.text()
            _, err = self.qemu.upload_host_file_to_guest(host_app_path, guest_app_path)
            
            if err:
                idaapi.warning(err)
                self._reload_layout()
            else:
                idaapi.info(f"File has uploaded to '{guest_app_path}' successfully!")

            return

    def btn_save_config_clicked(self):
        if self._validate_input():
            guest_app_path = self.box_guest_app_path.text()
            debug_app_parameter = self.box_debug_app_parameter.text()
            debug_dir = self.box_debug_dir.text()

            if debug_dir == "":
                debug_dir = os.path.dirname(self.box_guest_app_path.text())

            # Set ida debugging option
            ida_dbg.load_debugger("linux", True)
            ida_nalt.set_root_filename(guest_app_path)
            ida_dbg.set_process_options(
                guest_app_path,
                debug_app_parameter,
                debug_dir,
                "127.0.0.1",
                "",
                self.qemu.get_debug_server_host_port()
            )

            return True

        return False

    def btn_restore_config_clicked(self):
        self.box_host_app_path.setText(get_loaded_binary_path())
        self.box_guest_app_path.setText(f"/root/{os.path.basename(get_loaded_binary_path())}")
        self.box_debug_dir.setText("")
        self.box_debug_app_parameter.setText("")
    
    def btn_quick_start_clicked(self):
        if self.btn_save_config_clicked() and not idaapi.is_debugger_on():
            success = ida_dbg.start_process() == 1

            if not success:
                idaapi.warning("Please check debugging directory or VM connection.")
            else:
                redock_all_windows()
        
    def btn_quick_attach_clicked(self):
        if self._reload_layout() and not idaapi.is_debugger_on():
            ida_dbg.load_debugger("linux", True)
            ida_dbg.set_process_options(
                None,
                None,
                None,
                "127.0.0.1",
                None,
                self.qemu.get_debug_server_host_port()
            )

            ida_dbg.attach_process()

