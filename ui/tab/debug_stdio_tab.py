import idaapi
import ida_kernwin

import logging

from PyQt5.QtWidgets import *

from ekko.store.profile import *
from ekko.ui.utils import *
from ekko.qemu.qemu import QEMU
from ekko.ui.widget.debug_output_view import DebugOutputView

class DebuggeeStdioTab(ida_kernwin.PluginForm):
    WINDOW_NAME = "Debuggee Standard Input/Output"
    DEFAULT_BUTTON_WIDTH = 70

    def __init__(self, vm_name):
        super().__init__()
        
        self.vm_name = vm_name
        self.logger = logging.getLogger(vm_name)
        self.qemu = QEMU.create_instance(vm_name)
        self.showed = False

    def OnClose(self, form):
        self.showed = False

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._create_widget()
        self._setup_layout()

    def Close(self):
        if self.showed:
            super().Close(options=(ida_kernwin.PluginForm.WCLS_SAVE |
                                    ida_kernwin.PluginForm.WCLS_DELETE_LATER))
    def Show(self):
        # Show window
        if not self.showed:
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

            self.showed = True
            return result
    
    def _create_widget(self):
        # Log view widget
        self.widget_debug_output_view = DebugOutputView(self.vm_name)

        # Menu for the input option button
        self.menu_debug_action = QMenu()
        self.menu_debug_action.addAction("Text", self.menu_select_text)
        self.menu_debug_action.addAction("Python", self.menu_select_python)
        self.menu_debug_action.addAction("Clear", self.menu_select_clear)

        # input option button
        self.btn_input_option = QPushButton("Text")
        self.btn_input_option.setFixedWidth(self.DEFAULT_BUTTON_WIDTH)
        self.btn_input_option.setFixedHeight(25)
        self.btn_input_option.setMenu(self.menu_debug_action)

        # input text box
        self.box_debug_input = QLineEdit("")
        self.box_debug_input.setFixedHeight(25)
        self.box_debug_input.returnPressed.connect(self.box_debug_input_return_pressed)

    def _setup_layout(self):
        debug_output_hbox = make_hbox(self.widget_debug_output_view)
        debug_output_hbox.setContentsMargins(0, 0, 0, 0)
        
        debug_input_hbox = make_hbox(
            self.btn_input_option, self.box_debug_input,
        )
        debug_input_hbox.setContentsMargins(0, 0, 0, 0)

        main_layout = make_vbox(
            debug_output_hbox,
            debug_input_hbox
        )
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.parent.setLayout(main_layout)
    
    def menu_select_text(self):
        self.btn_input_option.setText("Text")
    
    def menu_select_python(self):
        self.btn_input_option.setText("Python")
    
    def menu_select_clear(self):
        self.widget_debug_output_view.clear_output()
    
    def box_debug_input_return_pressed(self):
        if not self.qemu.is_debug_server_connected():
            ida_kernwin.warning("Remote debug server is not connected.")
            return

        cmd = self.box_debug_input.text()
        cmd_type = self.btn_input_option.text()

        if cmd_type == "Text":
            _, err = self.qemu.send_debug_input(cmd + '\n')
        elif cmd_type == "Python":
            try:
                ldict={}
                exec(f"cmd={cmd}",globals(), ldict) # be careful
                cmd = str(ldict['cmd'])
            except Exception as e:
                ida_kernwin.warning(str(e))
                return
                
            _, err = self.qemu.send_debug_input(cmd)

        if err:
            ida_kernwin.warning(err)

        self.box_debug_input.setText("")
        return 
