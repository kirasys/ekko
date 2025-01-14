import traceback
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIntValidator

from ekko.ui.utils import *
from ekko.store.profile import ProfileStore

class VMCreateDialog(QDialog):
    DEFAULT_LABEL_WIDTH = 200
    DEFAULT_LINE_EDIT_WIDTH = 300

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        # Setting window title
        self.setWindowTitle("Create a new virutal machine")

        self._create_widget()
        self._setup_layout()
    
    def _create_widget(self):
        ####### Main widgets #######
        # OK | Cancel button
        self.btn_ok = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.btn_ok.accepted.connect(self.btn_ok_clicked)
        self.btn_ok.rejected.connect(self.btn_cancle_clicked)

        self.label_error = QLabel("")
        self.label_error.setStyleSheet("color: red; font-weight: bold;")

        ####### Configuration widgets #######
        # Working directory 
        self.box_work_dir = QLineEdit()
        self.box_work_dir.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)
        self.box_work_dir.setReadOnly(True)

        self.btn_browse_work_dir = QPushButton("...")
        self.btn_browse_work_dir.clicked.connect(self.btn_browse_work_dir_clicked)

        # QEMU binary path
        self.box_qemu_path = QLineEdit()
        self.box_qemu_path.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.btn_browse_qemu_path = QPushButton("...")
        self.btn_browse_qemu_path.clicked.connect(self.btn_browse_qemu_path_clicked)
        
        # Virtual machine name
        self.box_vm_name = QLineEdit()
        self.box_vm_name.setMaxLength(30)

        # Operating system type
        self.label_os_type = QLabel("")
        self.btn_type_windows = QRadioButton('Windows')
        self.btn_type_windows.toggled.connect(self.btn_os_type_clicked)
        self.btn_type_linux = QRadioButton('Linux')
        self.btn_type_linux.toggled.connect(self.btn_os_type_clicked)
        self.btn_type_linux.setChecked(True)
        
        ####### Hardware widgets #######
        # Cpu architecture
        self.label_cpu_architecture = QLabel("")
        self.btn_cpu_x86_64 = QRadioButton('x86_64')
        self.btn_cpu_x86_64.toggled.connect(self.btn_cpu_architecture_clicked)
        self.btn_cpu_x86_64.setChecked(True)
        self.btn_cpu_x86_64.setAttribute(Qt.WA_TransparentForMouseEvents) # Todo
        
        # Number of processors.
        self.box_processor = QLineEdit('1')
        self.box_processor.setValidator(QIntValidator())

        # Memory capacity.
        self.box_memory = QLineEdit('1024')
        self.box_memory.setValidator(QIntValidator())

        # Disk capacity
        self.box_disk = QLineEdit('32')
        self.box_disk.setValidator(QIntValidator())

        # Cdrom image path
        self.box_cdrom_path = QLineEdit()
        self.box_cdrom_path.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.btn_browse_cdrom = QPushButton("...")
        self.btn_browse_cdrom.clicked.connect(self.btn_browse_cdrom_clicked)

        ####### Advanced option widgets #######
        # Accelerating QEMU option (kvm or haxm)
        self.btn_accel_qemu = QCheckBox("Accelerating QEMU (kvm/haxm)")

    def _setup_layout(self):
        ########## Layout ##########
        # Setting configuration layout
        self.group_config = QGroupBox("Configuration")
        
        vbox = make_vbox(
            make_hbox(
                ("Select working directory: ", self.DEFAULT_LABEL_WIDTH),
                self.box_work_dir,
                self.btn_browse_work_dir
            ),
            make_hbox(
                ("Select QEMU installation path: ", self.DEFAULT_LABEL_WIDTH),
                self.box_qemu_path,
                self.btn_browse_qemu_path
            ),
            make_hbox(
                ("Virtual machine name: ", self.DEFAULT_LABEL_WIDTH),
                self.box_vm_name,
            ),
            make_hbox(
                ("Operating system:", self.DEFAULT_LABEL_WIDTH),
                self.btn_type_linux,
                self.btn_type_windows
            )
        )
        self.group_config.setLayout(vbox)

        # Setting hardware layout
        self.group_hardware = QGroupBox("Hardware")

        vbox = make_vbox(
            make_hbox(
                ("Cpu architecture:", self.DEFAULT_LABEL_WIDTH),
                self.btn_cpu_x86_64
            ),
            make_hbox(
                ("Number of processors: ", self.DEFAULT_LABEL_WIDTH),
                self.box_processor
            ),
            make_hbox(
                ("Memory capacity (MB): ", self.DEFAULT_LABEL_WIDTH),
                self.box_memory
            ),
            make_hbox(
                ("Disk capacity (GB): ", self.DEFAULT_LABEL_WIDTH),
                self.box_disk
            ),
            make_hbox(
                ("Select CD/DVD image: ", self.DEFAULT_LABEL_WIDTH),
                self.box_cdrom_path,
                self.btn_browse_cdrom
            )
        )

        self.group_hardware.setLayout(vbox)

        # Setting advanced option layout
        self.group_advanced = QGroupBox("Advanced")

        vbox = make_vbox(
            self.btn_accel_qemu
        )

        self.group_advanced.setLayout(vbox)

        # Setting main layout
        vbox = make_vbox(
            self.group_config,
            " ",
            self.group_hardware,
            " ",
            self.group_advanced,
            make_hbox(self.label_error, self.btn_ok)
        )

        self.setLayout(vbox)
    
    def _validate_input(self):
        if self.box_work_dir.text() == "":
            self.label_error.setText("Please select the working directory")
        elif self.box_qemu_path.text() == "":
            self.label_error.setText("Please select QEMU installation path")
        elif self.box_vm_name.text() == "":
            self.label_error.setText("Please enter the virtual machine name")
        elif self.box_processor.text() == "":
            self.label_error.setText("Please enter the number of processers")
        elif self.box_memory.text() == "":
            self.label_error.setText("Please enter the memory capacity")
        elif self.box_disk.text() == "":
            self.label_error.setText("Please enter the disk capacity")
        else:
            return True
        return False

    def btn_ok_clicked(self):
        if self._validate_input():
            try:
                ProfileStore.create_vm_profile(
                    work_dir = self.box_work_dir.text(),
                    qemu_path = self.box_qemu_path.text(),
                    vm_name = self.box_vm_name.text(),
                    os_type = self.label_os_type.text(),
                    cpu_architecture = self.label_cpu_architecture.text(),
                    number_of_processors = self.box_processor.text(),
                    memory_capacity = self.box_memory.text(),
                    disk_capacity = self.box_disk.text(),
                    cdrom = self.box_cdrom_path.text(),
                    acceleration = self.btn_accel_qemu.isChecked()
                )
            except Exception as e:
                self.label_error.setText("Can't create new VM profile")
                print(str(e))
                traceback.print_exc()
            else:
                from ekko.ui.tab.vmtab import VMControlTab
                VMControlTab(self.box_vm_name.text()).Show()
                self.close()

    def btn_cancle_clicked(self):
        self.close() 

    def btn_browse_work_dir_clicked(self):
        directory = QFileDialog.getExistingDirectory(self, 'Select working directory')
        if directory:
            self.box_work_dir.setText(directory)
    
    def btn_browse_qemu_path_clicked(self):
        directory = QFileDialog.getExistingDirectory(self, 'Select QEMU installtion path')
        if directory:
            self.box_qemu_path.setText(directory)

    def btn_browse_cdrom_clicked(self):
        filename = QFileDialog.getOpenFileName(self, 'Select CD/DVD image')
        if filename[0]:
            self.box_cdrom_path.setText(filename[0])
    
    def btn_os_type_clicked(self):
        btn = self.sender()
        if btn.isChecked():
            self.label_os_type.setText(btn.text())
        
    def btn_cpu_architecture_clicked(self):
        btn = self.sender()
        if btn.isChecked():
            self.label_cpu_architecture.setText(btn.text())
