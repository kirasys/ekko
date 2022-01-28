import idaapi
import ida_kernwin

import logging
import traceback

from PyQt5.QtWidgets import *

from ekko.store.profile import *
from ekko.ui.utils import *
from ekko.ui.widget.vmconfig import VMConfigWidget
from ekko.ui.widget.vmlog import VMLogWidget
from ekko.ui.widget.vmdebug import VMDebugWidget
from ekko.ui.widget.vmsnapshot import VMSnapshotWidget
from ekko.qemu.qemu import QEMU

class VMControlTab(ida_kernwin.PluginForm):
    DEFAULT_BUTTON_WIDTH = 60
    WINDOW_NAME = 'VM'

    def __init__(self, vm_name):
        super().__init__()
        
        self.vm_name = vm_name
        VMControlTab.WINDOW_NAME = vm_name
        self.logger = logging.getLogger(vm_name)
        self.qemu = QEMU.create_instance(vm_name)

    def OnClose(self, form):
        self.qemu.stop()

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._create_widget()
        self._setup_layout()

    def Show(self):
        # Show window
        result = ida_kernwin.PluginForm.Show(
            self, self.WINDOW_NAME,
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_MENU |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB)
        )

        # Dock windows
        redock_all_windows()

        return result
    
    def _create_widget(self):
        self.config_widget = VMConfigWidget(self.parent, self.vm_name)
        self.debug_widget = VMDebugWidget(self.parent, self.vm_name)
        self.snapshot_widget = VMSnapshotWidget(self.parent, self.vm_name)
        self.log_widget = VMLogWidget(self.parent, self.vm_name)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.config_widget, "Config")
        self.tabs.addTab(self.debug_widget, "Debug")
        self.tabs.addTab(self.snapshot_widget, "Snapshot")
        self.tabs.addTab(self.log_widget, "Log")

        self.btn_start = QPushButton("Start")
        self.btn_start.clicked.connect(self.btn_start_clicked)
        self.btn_start.setFixedWidth(self.DEFAULT_BUTTON_WIDTH)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.btn_stop_clicked)
        self.btn_stop.setFixedWidth(self.DEFAULT_BUTTON_WIDTH)

    def _setup_layout(self):
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
            ida_kernwin.warning("Fail to start QEMU")
            self.logger.error(str(e))
            traceback.print_exc()
        finally:
            ida_kernwin.hide_wait_box()
    
    def btn_stop_clicked(self):
        ida_kernwin.show_wait_box("Stopping QEMU...")
        try:
            self.qemu.stop()
        except Exception as e:
            ida_kernwin.warning(f"Fail to stop QEMU")
            self.logger.error(str(e))
            traceback.print_exc()
        finally:
            ida_kernwin.hide_wait_box()