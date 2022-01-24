from PyQt5.QtWidgets import *

from ekko.ui.utils import *
from ekko.profile import *
from ekko.ui.dialog.vmcreate import VMCreateDialog

class VMEditConfigDialog(VMCreateDialog):
    def __init__(self, parent, profile_name):
        super().__init__(parent)
        self.parent = parent
        self.profile_name = profile_name
        self.box_disk.setReadOnly(True) # Todo

        self._load_profile()

    def _setup_layout(self):
        ########## Layout ##########
        # Setting configuration layout
        self.group_config = QGroupBox("Configuration")
        
        vbox = make_vbox(
            make_hbox(
                ("Select QEMU installation path: ", self.LABEL_DEFAULT_WIDTH),
                self.box_qemu_path,
                self.btn_browse_qemu_path
            ),
            make_hbox(
                ("Virtual machine name: ", self.LABEL_DEFAULT_WIDTH),
                self.box_vm_name,
            ),
            make_hbox(
                ("Operating system:", self.LABEL_DEFAULT_WIDTH),
                self.btn_type_linux,
                self.btn_type_windows
            )
        )

        self.group_config.setLayout(vbox)

        # Setting hardware layout
        self.group_hardware = QGroupBox("Hardware")

        vbox = make_vbox(
            make_hbox(
                ("Cpu architecture:", self.LABEL_DEFAULT_WIDTH),
                self.btn_cpu_x86_64
            ),
            make_hbox(
                ("Number of processors: ", self.LABEL_DEFAULT_WIDTH),
                self.box_processor
            ),
            make_hbox(
                ("Memory capacity (MB): ", self.LABEL_DEFAULT_WIDTH),
                self.box_memory
            ),
            make_hbox(
                ("Disk capacity (GB): ", self.LABEL_DEFAULT_WIDTH),
                self.box_disk
            ),
            make_hbox(
                ("Select CD/DVD image: ", self.LABEL_DEFAULT_WIDTH),
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
    
    def _load_profile(self):
        profile = get_vm_profile(self.profile_name)
        
        # Load profile
        self.box_qemu_path.setText(profile.qemu_path)
        self.box_vm_name.setText(profile.name)

        if profile.cpu_architecture == 'x86_64':
            self.btn_cpu_x86_64.setChecked(True)

        if profile.os_type == 'Linux':
            self.btn_type_linux.setChecked(True)
        elif profile.os_type == 'Windows':
            self.btn_type_windows.setChecked(True)
        
        self.box_processor.setText(profile.number_of_processors)
        self.box_memory.setText(profile.memory_capacity)
        self.box_disk.setText(profile.disk_capacity)
        self.box_cdrom_path.setText(profile.cdrom)

        if profile.acceleration:
            self.btn_accel_qemu.setChecked(True)

    def _validate_input(self):
        if self.box_qemu_path.text() == "":
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
                update_vm_profile(
                    self.profile_name,
                    qemu_path = self.box_qemu_path.text(),
                    name = self.box_vm_name.text(),
                    os_type = self.label_os_type.text(),
                    cpu_architecture = self.label_cpu_architecture.text(),
                    number_of_processors = self.box_processor.text(),
                    memory_capacity = self.box_memory.text(),
                    disk_capacity = self.box_disk.text(),
                    cdrom = self.box_cdrom_path.text(),
                    acceleration = self.btn_accel_qemu.isChecked()
                )
            except Exception as e:
                self.label_error.setText("Can't edit VM profile")
                print(str(e))
            else:
                self.close()