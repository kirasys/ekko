import os
import time
import platform
import logging
import subprocess
import idaapi
import ida_dbg
import ida_kernwin

from ekko.utils import *
from ekko.store.profile import *
from ekko.qemu.qmp import QMPSocketServer
from ekko.qemu.debug_agent import DebugAgentClient
from ekko.qemu.debug_server import DebugServerClient

qemu_instance_map = {}

class QEMU:
    DISK_FILE_NAME = 'disk1.qcow'

    def __init__(self, vm_name, _):
        self.vm_name = vm_name
        self.logger = logging.getLogger(vm_name)
        self.qemu_process = None
        self.qemu_started = False
        self.qmp_server = None
        self.debug_agent = None
        self.debug_server = None
    
    @staticmethod
    def create_instance(vm_name):
        # Create once per VM profile
        if vm_name not in qemu_instance_map:
            qemu_instance_map[vm_name] = QEMU(vm_name, None)
        
        return qemu_instance_map[vm_name]

    """
    Return a qemu-system-* path according to the cpu architecture.
    """
    def get_qemu_system_path(self):
        profile = get_vm_profile(self.vm_name)

        if profile.cpu_architecture == 'x86_64':
            binary = 'qemu-system-x86_64'
        else:
            assert False, "Unsupported cpu architecture"
        
        return os.path.join(profile.qemu_path, binary)
    
    """
    Return a qemu-img binary path. 
    """
    def get_qemu_img_path(self):
        profile = get_vm_profile(self.vm_name)
        return os.path.join(profile.qemu_path, 'qemu-img')

    
    def get_create_disk_command(self):
        profile = get_vm_profile(self.vm_name)

        cmd  = f"{self.get_qemu_img_path()} "
        cmd += "create -f qcow2 "
        cmd += f"{os.path.join(profile.work_dir, self.DISK_FILE_NAME)} "
        cmd += f"{profile.disk_capacity}G"
        return cmd

    def get_start_command(self):
        profile = get_vm_profile(self.vm_name)

        # Convert the VM profile to cmd
        cmd  = f"{self.get_qemu_system_path()} "
        cmd += "-serial stdio "
        cmd += f"-hda {os.path.join(profile.work_dir, profile.disk_file)} "
        cmd += f"-smp {profile.number_of_processors} "
        cmd += f"-m {profile.memory_capacity} "
        
        if len(profile.cdrom) > 0:
            cmd += f"-cdrom {profile.cdrom} "
        
        if profile.acceleration is not None and profile.acceleration:
            if platform.system() == "Windows":
                cmd += f'-accel hax '
            elif platform.system() == "Linux":
                cmd += f'-enable-kvm '
        
        # Network setting
        cmd += "-net nic -net user"
        # Debug agent forwarding
        cmd += f",hostfwd=tcp::{self.debug_agent.get_fwd_port()}-:{self.debug_agent.get_port()}"
        # Debug server forwarding
        cmd += f",hostfwd=tcp::{self.debug_server.get_fwd_port()}-:{self.debug_server.get_port()} "
        
        # Device sttting
        # Debug server stdin forwarding (ttyS4)
        cmd += f"-chardev socket,id=ch0,server=on,wait=off,host=127.0.0.1,port={self.debug_server.get_stdin_fwd_port()} "
        cmd += f"-device pci-serial,chardev=ch0,id=serial0 "
        # Debug server stdout forwarding (ttyS5)
        cmd += f"-chardev socket,id=ch1,server=on,wait=off,host=127.0.0.1,port={self.debug_server.get_stdout_fwd_port()} "
        cmd += f"-device pci-serial,chardev=ch1,id=serial1 "
        
        # Socket server for MP
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
            self.logger.error("Invalid QEMU binary path")
            return False
        
        return True
    
    def is_qemu_started(self):
        return self.qemu_started

    def is_qemu_process_running(self):
        if self.qemu_process:
            return self.qemu_process.poll() is None
        return False
    
    def _create_disk(self, force=False):
        profile = get_vm_profile(self.vm_name)

        if not force and profile.disk_file is not None:
            return True

        try:
            proc = subprocess.run(self.get_create_disk_command())
            self.logger.debug(f"subprocess.run({self.get_create_disk_command()})")
        except Exception as e:
            return False

        # update the VM profile
        if proc.returncode == 0:
            update_vm_profile(
                self.vm_name,
                disk_file = self.DISK_FILE_NAME
            )

            self.logger.info(f"Disk file was created successfully ({self.DISK_FILE_NAME})")
            return True

        
        self.logger.error(f"Can't the create disk\n({self.get_create_disk_command()})")
        return False
    
    def _exit_qemu_process(self):
        if self.qemu_process is not None:
            self.qemu_process.kill()

            outs, errs = self.qemu_process.communicate(timeout=1)
            if errs != b'':
                self.logger.error("QEMU Error output: <br>\n%s" % errs.decode('utf-8'))

            self.qemu_process = None

    def start(self):
        if self.is_qemu_process_running():
            return False

        if not self.is_qemu_installed():
            return False
        
        if not self._create_disk():
            return False
        
        # QMP socket server must listen before running QEMU.
        self.qmp_server = QMPSocketServer(self.vm_name)
        self.qmp_server.listen()

        # Create the debug agent before running QEMU.
        self.debug_agent = DebugAgentClient(self.vm_name)

        # Create the debug server before running QEMU.
        self.debug_server = DebugServerClient(self.vm_name)
        
        self.qemu_process = subprocess.Popen(self.get_start_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        self.logger.debug(f"subprocess.run({self.get_start_command()})")
        
        # Handshake with QMP client
        if not self.qmp_server.handshake():
            self._exit_qemu_process()
            return False

        self.qemu_started = True
        self.logger.info("QEMU is started")
        return True

    def stop(self):
        if not self.is_qemu_started():
            return
        
        # Quit via QMP
        self.qmp_server.request_exit()

        # Quit force
        self._exit_qemu_process()

        # Close the qmp server
        self.qmp_server.close()
        self.qmp_server = None

        # Close the debug agent
        self.debug_agent.close()
        self.debug_agent = None

        # Close the debug server
        self.debug_server.close()
        self.debug_server = None

        self.qemu_started = False
        self.logger.info("QEMU is exited")
    
    ##################################################
    #                 QMP Functions                  #
    ##################################################
    def wait_qmp_server_connection(self):
        ida_kernwin.show_wait_box("Wait for snapshot completed...")

        try:
            alive = False
            while True:
                alive = self.qmp_server.health_check()
                if ida_kernwin.user_cancelled() or alive:
                    break
                
                time.sleep(0.3)
        finally:
            ida_kernwin.hide_wait_box()
            if alive:
                return alive, ""
            else:
                return alive, "Fail to connect to QMP"

    def inject_cdrom(self, iso_file):
        if not self.is_qemu_started():
            return None, "VM is not started."
        
        cdrom_file, err = self.qmp_server.get_cdrom_file()
        if err or cdrom_file == "":
            return None, "Please retry."

        if os.path.samefile(cdrom_file, iso_file):
            return "ISO image is already inserted", ""
        
        if cdrom_file:
            res, err = self.qmp_server.request_eject()
            if err:
                return res, err
        
        return self.qmp_server.request_insert_cdrom(iso_file)

    def take_snapshot(self, tag):
        if not self.is_qemu_started():
            return None, "VM is not started."

        if idaapi.is_debugger_on():
            self.debug_server.invoke_ioctl_save_debmod()
            self.debug_server.invoke_term_debugger()
            
        res, err = self.qmp_server.request_save_snapshot_hm(tag)

        #if idaapi.is_debugger_on():
        #    self.debug_server.invoke_init_debugger()
        #    self.debug_server.invoke_ioctl_restore_debmod()

        if err:
            return res, err
        
        return self.wait_qmp_server_connection()

    def load_snapshot(self, tag, snapshot_on_debugging):
        if not self.is_qemu_started():
            return None, "VM is not started."

        if idaapi.is_debugger_on():
            ida_dbg.exit_process()

        res, err = self.qmp_server.request_load_snapshot_hm(tag)
        if err:
            return res, err

        if snapshot_on_debugging:
            ida_dbg.set_process_options(
                "",
                "",
                "",
                "127.0.0.1",
                "",
                self.get_debug_server_host_port()
            )

            #success = ida_dbg.start_process() == 1
            #if not success:
            #    idaapi.warning("Please check debugging directory or VM connection.")
            #else:
            #    redock_all_windows()
        
        return self.wait_qmp_server_connection()
    
    def delete_snapshot(self, tag):
        if not self.is_qemu_started():
            return None, "VM is not started."

        return self.qmp_server.request_delete_snapshot_hm(tag)
    
    ##################################################
    #              Debug agent Functions             #
    ##################################################
    def stop_debug_agent(self):
        if self.is_qemu_started():
            self.debug_agent.exec("systemctl stop debug_agent")
            return True
        return False
    
    def restart_debug_agent(self):
        if self.is_qemu_started():
            self.debug_agent.exec("systemctl restart debug_agent")
            return True
        return False

    def is_debug_agent_connectable(self):
        if not self.is_qemu_started():
            return False

        ida_kernwin.show_wait_box("Connect to the debug agent...")
        try:
            connected = self.debug_agent.is_rpc_server_alive()
        finally:
            ida_kernwin.hide_wait_box()

        self.logger.debug(f"Debug agent connection({connected})")
        return connected
    
    def wait_debug_agent_connection(self):
        if not self.is_qemu_started():
            return False

        ida_kernwin.show_wait_box("Wait for debug agent connection...")

        try:
            while True:
                connected = self.debug_agent.is_rpc_server_alive()
                if ida_kernwin.user_cancelled() or connected:
                    break
                
                time.sleep(0.5)
        finally:
            ida_kernwin.hide_wait_box()
            return connected
    
    def upload_host_file_to_guest(self, hostfile, guestfile):
        if not self.is_qemu_started():
            return None, "QEMU is not started"

        res, err = self.debug_agent.open_file(guestfile, readonly=False)
        if not err:
            fn = res['fn']

            with open(hostfile, 'rb') as f:
                buf = f.read()

            res, err = self.debug_agent.write_file(fn, 0, buf, len(buf))
            if not err:
                 res, err = self.debug_agent.close_file(fn)
                 if not err:
                     self.logger.info(f"Upload host:{hostfile} to guest:{guestfile}")

        return res, err

    ##################################################
    #              Debug Server Functions            #
    ##################################################
    def get_debug_server_host_port(self):
        if self.debug_server:
            return self.debug_server.get_host_forward_port()
    
    def is_debug_server_connected(self):
        return (self.debug_server and \
                    self.debug_server.stdin_sock and \
                    self.debug_server.stdout_sock ) is not None
        
    def send_debug_input(self, data):
        if not self.is_qemu_started():
            return None, "QEMU is not started"
        
        return self.debug_server.send_input(data)
        

