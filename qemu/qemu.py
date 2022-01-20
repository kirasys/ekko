import os
import logging
import platform
import subprocess

from ekko.profile import *
from ekko.qemu.qmp import QMPSocketServer

class QEMU:
    DISK_FILE_NAME = 'disk1.qcow'

    def __init__(self, profile_name):
        self.profile_name = profile_name
        self.qemu_process = None
        self.qemu_started = False
        self.qmp_server = None
        
    """
    Return a qemu-system-* path according to the cpu architecture.
    """
    def get_qemu_system_path(self):
        profile = get_vm_profile(self.profile_name)

        if profile.cpu_architecture == 'x86_64':
            binary = 'qemu-system-x86_64'
        else:
            assert False, "Unsupported cpu architecture"
        
        return os.path.join(profile.qemu_path, binary)
    
    """
    Return a qemu-img binary path. 
    """
    def get_qemu_img_path(self):
        profile = get_vm_profile(self.profile_name)
        return os.path.join(profile.qemu_path, 'qemu-img')

    
    def get_create_disk_command(self):
        profile = get_vm_profile(self.profile_name)

        cmd  = f"{self.get_qemu_img_path()} "
        cmd += "create -f qcow2 "
        cmd += f"{os.path.join(profile.work_dir, self.DISK_FILE_NAME)} "
        cmd += f"{profile.disk_capacity}G"
        return cmd

    def get_start_command(self):
        profile = get_vm_profile(self.profile_name)

        # Convert the VM profile to cmd
        cmd  = f"{self.get_qemu_system_path()} "
        cmd += f"-hda {os.path.join(profile.work_dir, profile.disk_file)} "
        cmd += f"-smp {profile.number_of_processors} "
        cmd += f"-m {profile.memory_capacity} "
        
        if len(profile.cdrom) > 0:
            cmd += f"-cdrom {profile.cdrom} "
        
        if profile.acceleration is not None:
            if platform.system() == "Windows":
                cmd += f'-accel hax '
            elif profile.os_type == "Linux":
                cmd += f'-enable-kvm '
        
        # Socket server for QMP
        if self.qmp_server:
            cmd += f"-qmp tcp:localhost:{self.qmp_server.get_server_port()} "

        return cmd
    
    def is_qemu_installed(self):
        try:
            proc = subprocess.run([self.get_qemu_system_path(), "--version"], capture_output=True)
        except Exception as e:
            output = ''
        else:
            output = proc.stdout
        
        if b'QEMU emulator' not in output:
            logging.error("Invalid QEMU binary path")
            return False
        
        return True
    
    def _create_disk(self, force=False):
        profile = get_vm_profile(self.profile_name)

        if not force and profile.disk_file is not None:
            return True

        try:
            proc = subprocess.run(self.get_create_disk_command())
            logging.debug(f"subprocess.run({self.get_create_disk_command()})")
        except Exception as e:
            return False

        # update the VM profile
        if proc.returncode == 0:
            update_vm_profile(
                self.profile_name,
                disk_file = self.DISK_FILE_NAME
            )

            logging.info(f"Disk file was created successfully ({self.DISK_FILE_NAME})")
            return True

        
        logging.error(f"Can't the create disk\n({self.get_create_disk_command()})")
        return False
    
    def _exit_qemu_process(self):
        if self.qemu_process is not None:
            self.qemu_process.kill()

            outs, errs = self.qemu_process.communicate(timeout=1)
            print(outs)

            self.qemu_process = None

    def start(self):
        if self.qemu_started:
            return

        if not self.is_qemu_installed():
            return False
        
        if not self._create_disk():
            return False

        self.qemu_process = subprocess.Popen(self.get_start_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logging.debug(f"subprocess.run({self.get_start_command()})")
        
        # Accept QMP client
        self.qmp_server = QMPSocketServer()
        if not self.qmp_server.handshake():
            self._exit_qemu_process()
            return False

        self.qemu_started = True
        logging.info("QEMU is started")

    def stop(self):
        if not self.qemu_started:
            return
        
        # Quit via QMP
        self.qmp_server.execute("quit")

        # Quit force
        self._exit_qemu_process()

        # Close the qmp server
        self.qmp_server.close()
        self.qmp_server = None

        self.qemu_started = False
        logging.info("QEMU is exited")