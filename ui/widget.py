from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *
from ekko.ui.utils import *
from ekko.profile import *

class VMConfigWidget(QWidget):
    LABEL_DEFAULT_WIDTH = 150
    LABEL_VALUE_WIDTH = 300
    BUTTON_EDIT_WIDTH = 50

    def __init__(self, parent, profile_name):
        super(VMConfigWidget, self).__init__()
        self.parent = parent
        self.profile_name = profile_name

        self._create_widget()
        self._setup_layout()
        self._load_profile()

    def _create_widget(self):
        # Group box
        self.group_config = QGroupBox("Configuration")
        self.group_hardware = QGroupBox("Hardware")
        self.group_advanced = QGroupBox("Advanced")

        # Accelerating check box
        self.btn_accel_qemu = QCheckBox("Accelerating QEMU (kvm/haxm)")
        self.btn_accel_qemu.setAttribute(Qt.WA_TransparentForMouseEvents)

        # Edit button
        self.btn_edit = QPushButton("Edit")
        self.btn_edit.setFixedWidth(self.BUTTON_EDIT_WIDTH)
        self.btn_edit.clicked.connect(self.edit_button_clicked)

        # Label
        self.label_qemu_path = QLabel("")
        self.label_qemu_path.setFixedWidth(self.LABEL_VALUE_WIDTH)

        self.label_vm_name = QLabel("")
        self.label_vm_name.setFixedWidth(self.LABEL_VALUE_WIDTH)

        self.label_os_type = QLabel("")
        self.label_os_type.setFixedWidth(self.LABEL_VALUE_WIDTH)

        self.label_cpu_architecture = QLabel("")
        self.label_cpu_architecture.setFixedWidth(self.LABEL_VALUE_WIDTH)

        self.label_num_processor = QLabel("")
        self.label_num_processor.setFixedWidth(self.LABEL_VALUE_WIDTH)
        
        self.label_memory_capacity = QLabel("")
        self.label_memory_capacity.setFixedWidth(self.LABEL_VALUE_WIDTH)

        self.label_disk_capacity = QLabel("")
        self.label_disk_capacity.setFixedWidth(self.LABEL_VALUE_WIDTH)

        self.label_cdrom = QLabel("")
        self.label_cdrom.setFixedWidth(self.LABEL_VALUE_WIDTH)

    def _setup_layout(self):
        # Config layout
        vbox = make_vbox(
            make_hbox(
                ("QEMU binary path", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_qemu_path
            ),
            make_hbox(
                ("Virtual machine name", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_vm_name
            ),
            make_hbox(
                ("Operating system", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_os_type
            )
        )
        self.group_config.setLayout(vbox)

        # Hardware layout
        vbox = make_vbox(
            make_hbox(
                ("Cpu architecture", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_cpu_architecture
            ),
            make_hbox(
                ("Number of Processors", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_num_processor
            ),
            make_hbox(
                ("Memory capacity (MB)", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_memory_capacity
            ),
            make_hbox(
                ("Disk capacity (GB)", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_disk_capacity
            ),
            make_hbox(
                ("CD/DVD", self.LABEL_DEFAULT_WIDTH), ": ",
                self.label_cdrom
            )
        )
        self.group_hardware.setLayout(vbox)

        # Advanced layout
        vbox = make_vbox(
            self.btn_accel_qemu
        )
        self.group_advanced.setLayout(vbox)

        # main layout
        vbox = make_vbox(
            self.group_config,
            self.group_hardware,
            self.group_advanced,
            self.btn_edit
        )
        self.setLayout(vbox)
    
    def _load_profile(self):
        profile = get_vm_profile(self.profile_name)
        
        # Load profile
        self.label_qemu_path.setText(profile.qemu_path)
        self.label_vm_name.setText(profile.name)
        self.label_os_type.setText(profile.os_type)
        self.label_cpu_architecture.setText(profile.cpu_architecture)
        self.label_num_processor.setText(profile.number_of_processors)
        self.label_memory_capacity.setText(profile.memory_capacity)
        self.label_disk_capacity.setText(profile.disk_capacity)
        self.label_cdrom.setText(profile.cdrom)

        if profile.acceleration:
            self.btn_accel_qemu.setChecked(True)
        else:
            self.btn_accel_qemu.setChecked(False)

    def edit_button_clicked(self):
        from ekko.ui.dialog import VMEditConfigDialog
        dialog = VMEditConfigDialog(self.profile_name)
        dialog.exec_()

        # reload
        self._load_profile()
        