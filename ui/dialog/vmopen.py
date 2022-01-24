import os

from PyQt5.QtWidgets import *

from ekko.ui.utils import *
from ekko.profile import *

class VMOpenDialog(QDialog):
    BOX_PROFILE_PATH_WIDTH = 300

    def __init__(self):
        super().__init__()

        # Setting window title
        self.setWindowTitle("Open profile.json")

        ####### Main widgets #######
        # OK | Cancel button
        self.btn_ok = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.btn_ok.button(QDialogButtonBox.Ok).setText("Open")
        self.btn_ok.accepted.connect(self.btn_ok_clicked)
        self.btn_ok.rejected.connect(self.btn_cancle_clicked)

        self.label_error = QLabel("")
        self.label_error.setStyleSheet("color: red; font-weight: bold;")

        # Browse file button
        self.box_profile_path = QLineEdit()
        self.box_profile_path.setFixedWidth(self.BOX_PROFILE_PATH_WIDTH)

        self.btn_browse_profile_path = QPushButton("...")
        self.btn_browse_profile_path.clicked.connect(self.btn_browse_profile_path_clicked)

        # Setting main layout
        vbox = make_vbox(
            make_hbox(self.box_profile_path, self.btn_browse_profile_path),
            make_hbox(self.label_error, self.btn_ok)
        )

        self.setLayout(vbox)
    
    def btn_ok_clicked(self):
        work_dir = os.path.dirname(self.box_profile_path.text())

        if work_dir == "":
            self.label_error.setText("Please select the profile.json")
        else:
            try:
                profile = read_vm_profile(work_dir)
            except Exception as e:
                self.label_error.setText("Invalid VM profile")
                print(str(e))
            else:
                # Open new tab
                from ekko.ui.tab import VMControlTab
                VMControlTab(profile.name).Show()
                self.close()

    def btn_cancle_clicked(self):
        self.close()
    
    def btn_browse_profile_path_clicked(self):
        filename = QFileDialog.getOpenFileName(self, "Open", "", "JSON (*.json)")
        if filename[0]:
            self.box_profile_path.setText(filename[0])