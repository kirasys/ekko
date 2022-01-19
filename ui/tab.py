import traceback
from turtle import right
import idaapi
import ida_kernwin

from PyQt5.QtWidgets import *

from ekko.profile import *
from ekko.ui.utils import *
from ekko.ui.widget.vmconfig import VMConfigWidget
from ekko.ui.widget.qemulog import QemuLogWidget
from ekko.qemu.qemu import QEMU

class VMControlTab(ida_kernwin.PluginForm):
    BUTTON_START_WIDTH = 60

    def __init__(self, profile_name):
        super(VMControlTab, self).__init__()
        
        self.profile_name = profile_name
        self.qemu = QEMU(profile_name)

    def OnClose(self, form):
        self.qemu.stop()

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._setup_ui()

    def Show(self):
        # Show window
        result = ida_kernwin.PluginForm.Show(
            self, self.profile_name,
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_MENU |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB)
        )

        # Set location
        if idaapi.find_widget('IDA View-A') is None:
            idaapi.set_dock_pos(self.profile_name, None, idaapi.DP_FLOATING)
        else:
            idaapi.set_dock_pos(self.profile_name, 'IDA View-A', idaapi.DP_TAB)

        return result

    def _setup_ui(self):
        self.config_widget = VMConfigWidget(self, self.profile_name)
        self.log_widget = QemuLogWidget(self, self.profile_name)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.config_widget, "Config")
        self.tabs.addTab(self.log_widget, "Log")

        self.btn_start = QPushButton("Start")
        self.btn_start.clicked.connect(self.btn_start_clicked)
        self.btn_start.setFixedWidth(self.BUTTON_START_WIDTH)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.btn_stop_clicked)
        self.btn_stop.setFixedWidth(self.BUTTON_START_WIDTH)

        main_layout = make_vbox(
            make_hbox(self.btn_start, self.btn_stop),
            self.tabs
        )

        self.parent.setLayout(main_layout)
    
    def btn_start_clicked(self):
        ida_kernwin.show_wait_box("Starting QEMU...")
        try:
            self.qemu.start()
        except Exception as e:
            ida_kernwin.warning(f"Can't start QEMU : {str(e)}")
            traceback.print_exc()
        finally:
            ida_kernwin.hide_wait_box()
    
    def btn_stop_clicked(self):
        ida_kernwin.show_wait_box("Stopping QEMU...")
        try:
            self.qemu.stop()
        except Exception as e:
            ida_kernwin.warning(f"Can't stop QEMU : {str(e)}")
        finally:
            ida_kernwin.hide_wait_box()