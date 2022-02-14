import idaapi
import ida_nalt
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt

def make_hbox(*children, align_left=False, align_right=False):
    hbox = QtWidgets.QHBoxLayout()
    hbox.setAlignment(Qt.AlignTop)

    if align_right:
        hbox.addStretch()

    for child in children:
        if issubclass(type(child), QtWidgets.QWidget):
            hbox.addWidget(child)
        elif issubclass(type(child), QtWidgets.QLayout):
            hbox.addLayout(child)
        elif type(child) is tuple:
            text, width = child
            label = QtWidgets.QLabel(text)
            label.setFixedWidth(width)
            hbox.addWidget(label)
        elif type(child) is str:
            if child == " ":
                hbox.addWidget(make_hblank())
            else:
                hbox.addWidget(QtWidgets.QLabel(child))
    
    if align_left:
        hbox.addStretch()
    return hbox

def make_vbox(*children):
    vbox = QtWidgets.QVBoxLayout()
    vbox.setAlignment(Qt.AlignTop)
    
    for child in children:
        if issubclass(type(child), QtWidgets.QWidget):
            vbox.addWidget(child)
        elif issubclass(type(child), QtWidgets.QLayout):
            vbox.addLayout(child)
        elif type(child) is tuple:
            text, width = child
            label = QtWidgets.QLabel(text)
            label.setFixedWidth(width)
            vbox.addWidget(label)
        elif type(child) is str:
            if child == " ":
                vbox.addWidget(make_hblank())
            else:
                vbox.addWidget(QtWidgets.QLabel(child))
    return vbox

def make_vblank():
    label = QtWidgets.QLabel("")
    label.setFixedHeight(1)
    return label

def make_hblank():
    label = QtWidgets.QLabel("")
    label.setFixedWidth(3)
    return label

def redock_all_windows():
    from ekko.ui.tab.vmtab import VMControlTab

    # Set location of VMControlTab
    if idaapi.find_widget(VMControlTab.WINDOW_NAME):
        if idaapi.find_widget('Structures') is None:
            idaapi.set_dock_pos(VMControlTab.WINDOW_NAME, None, idaapi.DP_FLOATING)
        else:
            idaapi.set_dock_pos(VMControlTab.WINDOW_NAME, 'Structures', idaapi.DP_TAB)

    from ekko.ui.tab.interactive_debug_shell import InteractiveDebugShell
    
    # Set location of InteractiveDebugShell
    if idaapi.find_widget(InteractiveDebugShell.WINDOW_NAME):
        if idaapi.find_widget('Output') is None:
            idaapi.set_dock_pos(InteractiveDebugShell.WINDOW_NAME, None, idaapi.DP_FLOATING)
        else:
            idaapi.set_dock_pos(InteractiveDebugShell.WINDOW_NAME, 'Output', idaapi.DP_TAB)