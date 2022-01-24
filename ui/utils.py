import ida_nalt
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt

def make_hbox(*children, align_left=False):
    hbox = QtWidgets.QHBoxLayout()
    hbox.setAlignment(Qt.AlignTop)

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