import os
import idaapi
import ida_dbg
import ida_nalt

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from ekko.utils import *
from ekko.ui.utils import *
from ekko.store.profile import *
from ekko.qemu.qemu import QEMU

class VMDebugWidget(QWidget):
    DEFAULT_LABEL_WIDTH = 180
    DEFAULT_LINE_EDIT_WIDTH = 250
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

    def _create_widget(self):
        # Menu for Debugger Button
        self.menu_debug_action = QMenu()
        self.menu_debug_action.addAction('Start process', self.menu_start_process)
        self.menu_debug_action.addAction('Attach to process', self.menu_attach_to_process)
        self.menu_debug_action.addAction('Pause process', self.menu_pause_process)
        self.menu_debug_action.addAction('Continue process', self.menu_continue_process)
        self.menu_debug_action.addAction('Stop process', self.menu_stop_process)

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

        self.btn_upload_lib = QPushButton("Upload")
        self.btn_upload_lib.setFixedWidth(self.SMALL_BUTTON_WIDTH)
        self.btn_upload_lib.clicked.connect(self.btn_upload_lib_clicked)

        self.btn_debug_action = QPushButton("")
        self.btn_debug_action.setFixedWidth(self.LARGE_BUTTON_WIDTH)
        self.btn_debug_action.setMenu(self.menu_debug_action)
        
        # Label
        self.debug_agent_status_label = QLabel("Debug agent must be installed for debugging.")
        self.debug_agent_status_label.setStyleSheet("font-weight: bold; text-decoration: underline")

        self.label_error = QLabel("")
        self.label_error.setStyleSheet("color: red; font-weight: bold;")
        
        # Group box
        self.group_config = QGroupBox("Configuration")
        self.group_debug = QGroupBox("Debugging")

        # Text box
        self.box_debug_dest_path = QLineEdit('/root')
        self.box_debug_dest_path.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_app_path = QLineEdit(get_loaded_binary_path())
        self.box_app_path.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_lib_path = QLineEdit('')
        self.box_lib_path.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_parameters = QLineEdit('')
        self.box_parameters.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        # Debug output window
        from ekko.ui.tab.debug_stdio_tab import DebuggeeStdioTab
        self.tab_debug_stdio = DebuggeeStdioTab(self.vm_name)
    
    def _setup_layout(self):
        # config layout
        vbox = make_vbox(
            make_hbox(
                ("Debugging directory in guest", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_debug_dest_path,
                align_left=True,
            ),
            make_hbox(
                ("Application binary", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_app_path, self.btn_upload_app,
                align_left=True,
            ),
            make_hbox(
                ("Libirary files (optional)", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_lib_path, self.btn_upload_lib,
                align_left=True,
            ),
            make_hbox(
                ("Parameters (optional)", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_parameters,
                align_left=True,
            ),
        )
        self.group_config.setLayout(vbox)

        # debug layout
        vbox = make_vbox(
            make_hbox(
                "Debugger operation :", self.btn_debug_action,
                align_left=True
            ),
        )
        self.group_debug.setLayout(vbox)
        
        # main layout
        main_layout = make_vbox(
            ("Warning: All debugging-related operations are executed as root."),
            make_hbox(
                self.debug_agent_status_label,
                self.btn_install, self.btn_reconnect,
                align_left=True,
            ),
            make_hbox(self.group_config, align_left=True),
            make_hbox(self.group_debug, align_left=True),
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
            self.group_debug.show()
            
            # Show the debug output tab
            self.tab_debug_stdio.Show()
            
            return True
        else:
            # Update the status label
            self.debug_agent_status_label.setText("Debug agent must be installed for debugging.")

            # Change the install button text.
            self.btn_install.setText("Install")

            # Hide groups
            self.group_config.hide()
            self.group_debug.hide()

            # Hide the debug output tab
            self.tab_debug_stdio.Close()

            return False

    def btn_install_clicked(self):
        if not self.qemu.is_qemu_started():
            idaapi.warning("Please start VM first!")
            return

        from ekko.ui.dialog.install_debug_agent import DebugAgentInstallDialog
        dialog = DebugAgentInstallDialog(self.parent, self.vm_name)
        dialog.exec_()

        self._reload_layout()
    
    def btn_reconnect_clicked(self):
        if not self.qemu.is_qemu_started():
            idaapi.warning("Please start VM first!")
            return

        if self.qemu.wait_debug_agent_connection():
            self._reload_layout()
    
    def _validate_input(self):
        guest_dir = self.box_debug_dest_path.text()
        if guest_dir == "":
            idaapi.warning("Please enter a destination directory")
            return False
        
        app_path = self.box_app_path.text()
        if app_path == "":
            idaapi.warning("Please enter an apllication binary path")
            return False
        
        if not os.path.isfile(app_path):
            idaapi.warning("Invalid apllication binary path")
            return False
        
        return True

    def btn_upload_app_clicked(self):
        if self._validate_input() and self._reload_layout():
            app_path  = self.box_app_path.text()
            guest_dir = self.box_debug_dest_path.text()
            guest_file = unix_path_join(guest_dir, os.path.basename(app_path))
            _, err = self.qemu.upload_host_file_to_guest(app_path, guest_file)
            
            if err:
                idaapi.warning(err)
                self._reload_layout()
            else:
                idaapi.info(f"File has uploaded to '{guest_file}' successfully!")

            return

    def btn_upload_lib_clicked(self):
        pass
    
    def menu_start_process(self):
        if self._validate_input() and self._reload_layout() and not idaapi.is_debugger_on():
            app_path  = self.box_app_path.text()
            guest_dir = self.box_debug_dest_path.text()
            guest_file = unix_path_join(guest_dir, os.path.basename(app_path))
            parameters = self.box_parameters.text()

            ida_dbg.load_debugger("qemu_linux", True)
            ida_nalt.set_root_filename(guest_file)
            ida_dbg.set_process_options(
                guest_file,
                parameters,
                guest_dir,
                "127.0.0.1",
                "",
                self.qemu.get_debug_server_host_port()
            )
            
            success = ida_dbg.start_process() == 1
            if not success:
                idaapi.warning("Please check debugging directory or VM connection.")
            else:
                redock_all_windows()

    def menu_attach_to_process(self):
        if self._reload_layout() and not idaapi.is_debugger_on():
            ida_dbg.load_debugger("qemu_linux", True)
            ida_dbg.set_process_options(
                "",
                "",
                "",
                "127.0.0.1",
                "",
                self.qemu.get_debug_server_host_port()
            )

            ida_dbg.attach_process()

    def menu_pause_process(self):
        if idaapi.is_debugger_on():
            ida_dbg.suspend_process()
    
    def menu_continue_process(self):
        if idaapi.is_debugger_on():
            ida_dbg.continue_process()
    
    def menu_stop_process(self):
        if idaapi.is_debugger_on():
            ida_dbg.exit_process()