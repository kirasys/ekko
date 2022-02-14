import idaapi

from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt

from ekko.ui.utils import *
from ekko.store.snapshot import SnapshotStore

class CreateSnapshotDialog(QDialog):
    DEFAULT_LABEL_WIDTH = 80
    DEFAULT_LINE_EDIT_WIDTH = 250

    def __init__(self, parent, vm_name):
        super().__init__(parent)
        self.parent = parent
        self.vm_name = vm_name
        self.snapshot_created = False

        # Setting window title
        self.setWindowTitle("Create a new snaphost")

        self._create_widget()
        self._setup_layout()
    
    def _create_widget(self):
        # Line edit
        self.box_name = QLineEdit('')
        self.box_name.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        # Text edit
        self.box_description = QLineEdit('')
        self.box_description.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        # OK | Cancel button
        self.btn_ok = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.btn_ok.accepted.connect(self.btn_ok_clicked)
        self.btn_ok.rejected.connect(self.btn_cancle_clicked)

        # Label
        self.label_error = QLabel("")
        self.label_error.setStyleSheet("color: red; font-weight: bold;")
    
    def _setup_layout(self):
        # information group

        # main layout
        vbox = make_vbox(
            make_vbox(
                make_hbox(
                    ("Name: ", self.DEFAULT_LABEL_WIDTH),
                    self.box_name
                ),
                make_hbox(
                    ("Description: ", self.DEFAULT_LABEL_WIDTH),
                    self.box_description
                ),
            ),
            make_hbox(self.label_error, self.btn_ok)
        )

        self.setLayout(vbox)
    
    def _validate_input(self):
        if self.box_name.text() == "":
            self.label_error.setText("Please enter the snapshot name")
        else:
            return True
        return False

    def btn_ok_clicked(self):
         if self._validate_input():
            SnapshotStore.create_snapshot_info(
                self.vm_name,
                name = self.box_name.text(),
                description = self.box_description.text(),
                on_debugging = str(idaapi.is_debugger_on()),
                address = hex(idaapi.get_ip_val()) if idaapi.get_ip_val() else ""
            )
            self.snapshot_created = True
            self.close()
    
    def btn_cancle_clicked(self):
        self.close()