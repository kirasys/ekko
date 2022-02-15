import os
import time
import logging
import threading

import idaapi
import ida_kernwin

from PyQt5.QtWidgets import *
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import pyqtSignal

from ekko.ui.utils import *
from ekko.qemu.qemu import QEMU
from ekko.store.profile import ProfileStore
from ekko.store.stdio import StdioStore

class InteractiveDebugShell(ida_kernwin.PluginForm):
    WINDOW_NAME             = "Interactive debug shell"
    DEFAULT_BUTTON_WIDTH    = 70
    OBSERVER_CHECK_INTERVAL = 1
    BOX_OUTPUT_MAX_CAPACITY = 1024 * 1024 * 2 # 2MB

    def __init__(self, vm_name):
        super().__init__()
        
        # Update window name
        InteractiveDebugShell.WINDOW_NAME = f"Interactive debug shell ({vm_name})"

        self.vm_name = vm_name
        self.logger = logging.getLogger(vm_name)
        self.qemu = QEMU.create_instance(vm_name)
        self.showed = False

        self.observer_activated = False
        self.observer_handle = None

    def OnClose(self, form):
        self.showed = False

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._create_widget()
        self._setup_layout()

    def Close(self):
        if self.showed:
            self.showed = False

            self.stop_stdio_file_update_observer()

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

            # Start output updater
            self.start_stdio_file_update_observer()

            # Dock windows
            redock_all_windows()

            self.showed = True
            return result
    
    def _create_widget(self):
        # Menu for the input option button
        self.menu_debug_action = QMenu()
        self.menu_debug_action.addAction("Text", self.menu_select_text)
        self.menu_debug_action.addAction("Python", self.menu_select_python)
        self.menu_debug_action.addAction("Clear", self.menu_select_clear)

        # input type button
        self.btn_input_type = QPushButton("Text")
        self.btn_input_type.setFixedWidth(self.DEFAULT_BUTTON_WIDTH)
        self.btn_input_type.setFixedHeight(25)
        self.btn_input_type.setMenu(self.menu_debug_action)

        # input box
        self.box_input = QLineEdit("")
        self.box_input.setFixedHeight(25)
        self.box_input.returnPressed.connect(self.box_input_return_pressed)
        
        # output box
        self.box_output = SafeQPlainTextEdit("")
        self.box_output.setFont(QFont('Consolas', 10))
        self.box_output.setReadOnly(True)

        self.box_output.textUpdated.connect(self.box_output_update_text)

    def _setup_layout(self):
        debug_output_hbox = make_hbox(self.box_output)
        debug_output_hbox.setContentsMargins(0, 0, 0, 0)
        
        debug_input_hbox = make_hbox(
            self.btn_input_type, self.box_input,
        )
        debug_input_hbox.setContentsMargins(0, 0, 0, 0)

        main_layout = make_vbox(
            debug_output_hbox,
            debug_input_hbox
        )
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.parent.setLayout(main_layout)

    def menu_select_text(self):
        print(self.box_output.textCursor().atBlockStart())

        self.btn_input_type.setText("Text")
    
    def menu_select_python(self):
        self.btn_input_type.setText("Python")
    
    def menu_select_clear(self):
        self.box_output.clear()
        StdioStore.truncate_stdio_file(self.vm_name)
        
    def _interpret_input(self, type, input):
        if type == "Text":
            return input.encode('utf-8') + b'\n', ""
        elif type == "Python":
            try:
                ldict={}
                exec(f"input={input}", globals(), ldict) # be careful
                
                input = ldict['input']
                if isinstance(input, str):
                    return input.encode('latin-1'), ""
                elif isinstance(input, bytes):
                    return input, ""
                else:
                    return None, "Invalid expression!"

            except Exception as e:
                self.logger.error(e, exc_info=True)
                return None, str(e)

    def box_input_return_pressed(self):
        input, err = self._interpret_input(
            self.btn_input_type.text(),
            self.box_input.text(),
        )

        if err:
            ida_kernwin.warning(err)
            return

        _, err = self.qemu.send_stdin_to_debuggee(input)

        if err:
            ida_kernwin.warning(err)
            return

        # truncate input
        self.box_input.setText("")
        return

    def box_output_update_text(self, offset):
        if offset > self.BOX_OUTPUT_MAX_CAPACITY:
            self.box_output.setPlainText(
                self.box_output.toPlainText()[:offset//2]
            )

        self.box_output.insertPlainText(
            StdioStore.get_stdio_file(
                self.vm_name,
                offset,
            ).decode('utf-8', errors="backslashreplace")
        )

        self.box_output.moveCursor(QTextCursor.End)

    def start_stdio_file_update_observer(self):
        if self.observer_activated:
            return

        # Start stdout worker
        self.qemu.start_stdout_file_updater()

        self.observer_activated = True
        self.observer_handle = threading.Thread(target=self._stdio_file_update_observer)
        self.observer_handle.start()

    def stop_stdio_file_update_observer(self):
        if not self.observer_activated:
            return

        ida_kernwin.show_wait_box("Wait to close stdout channel..")

        try:
            self.qemu.stop_stdout_file_updater()

            self.observer_activated = False
            self.observer_handle.join()
        finally:
            ida_kernwin.hide_wait_box()

    def _stdio_file_update_observer(self):
        profile = ProfileStore.get_vm_profile(self.vm_name)
        prev_filesize = 0

        while self.observer_activated:
            cur_filesize = os.stat(profile.stdio_file).st_size

            if cur_filesize == prev_filesize:
                time.sleep(self.OBSERVER_CHECK_INTERVAL)
                continue
            
            self.box_output.emit_text_update(prev_filesize)
            
            prev_filesize = cur_filesize
        
        print("close")
            
class SafeQPlainTextEdit(QPlainTextEdit):
    textUpdated = pyqtSignal(int)

    def __init__(self, text=""):
        super().__init__(text)
    
    def emit_text_update(self, offset):
        try:
            self.textUpdated.emit(offset)
        except RuntimeError:
            return