import os
import time
import platform
import logging
import subprocess
import idaapi
import ida_dbg
import ida_kernwin

from ekko.utils import *
from ekko.store.profile import ProfileStore
from ekko.qemu.qmp import QMPSocketServer
from ekko.qemu.debug_agent import DebugAgentClient
from ekko.qemu.debug_server import DebugServerClient

qemu_instance_map = {}

class QEMU:
    DISK_FILE_NAME = 'disk1.qcow'
    BASE_NODE_NAME = 'base-node'
    
    IDA_WAIT_TIMEOUT = 0.3
    QEMU_START_WAIT_BOX_MESSAGE = "Starting QEMU..."
    QEMU_STOP_WAIT_BOX_MESSAGE = "Stopping QEMU..."
    QMP_SERVER_WAIT_MESSAGE = "Wait for qmp server connection..."
    QMP_SERVER_JOB_WAIT_MESSAGE = "Wait for job to complete..."
    DEBUG_AGENT_WAIT_MESSAGE = "Wait for debug agent connection..."
    

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
        profile = ProfileStore.get_vm_profile(self.vm_name)

        if profile.cpu_architecture == 'x86_64':
            binary = 'qemu-system-x86_64'
        else:
            assert False, "Unsupported cpu architecture"
        
        return os.path.join(profile.qemu_path, binary)
    
    """
    Return a qemu-img binary path. 
    """
    def get_qemu_img_path(self):
        profile = ProfileStore.get_vm_profile(self.vm_name)
        return os.path.join(profile.qemu_path, 'qemu-img')

    
    def get_create_disk_command(self):
        profile = ProfileStore.get_vm_profile(self.vm_name)

        cmd  = f"{self.get_qemu_img_path()} "
        cmd += "create -f qcow2 "
        cmd += f"{os.path.join(profile.work_dir, self.DISK_FILE_NAME)} "
        cmd += f"{profile.disk_capacity}G"
        return cmd

    def get_start_command(self):
        profile = ProfileStore.get_vm_profile(self.vm_name)
        
        cmd  = f"{self.get_qemu_system_path()} "
        
        # Boot device
        cmd += f"-blockdev node-name={self.BASE_NODE_NAME},"
        cmd += f"driver=qcow2,file.driver=file,file.filename={os.path.join(profile.work_dir, profile.disk_file)} "
        cmd += f"-device virtio-blk,drive={self.BASE_NODE_NAME},id=virtio0 "
        # CPU
        cmd += f"-smp {profile.number_of_processors} "
        # Memory
        cmd += f"-m {profile.memory_capacity} "        
        
        # CD/DVD
        if len(profile.cdrom) > 0:
            cmd += f"-cdrom {profile.cdrom} "
        
        # Acceleration
        if profile.acceleration is not None and profile.acceleration:
            if platform.system() == "Windows":
                cmd += f'-accel hax '
            elif platform.system() == "Linux":
                cmd += f'-enable-kvm '
        
        # Network device
        cmd += "-net nic -net user"
        # Debug agent forwarding
        cmd += f",hostfwd=tcp::{self.debug_agent.get_fwd_port()}-:{self.debug_agent.get_port()}"
        # Debug server forwarding
        cmd += f",hostfwd=tcp::{self.debug_server.get_fwd_port()}-:{self.debug_server.get_port()} "
        # Debug server stdin forwarding (ttyS4)
        cmd += f"-chardev socket,id=ch0,server=on,wait=off,host=127.0.0.1,port={self.debug_server.get_stdin_fwd_port()} "
        cmd += f"-device pci-serial,chardev=ch0,id=serial0 "
        # Debug server stdout forwarding (ttyS5)
        cmd += f"-chardev socket,id=ch1,server=on,wait=off,host=127.0.0.1,port={self.debug_server.get_stdout_fwd_port()} "
        cmd += f"-device pci-serial,chardev=ch1,id=serial1 "
        
        # Socket server for MP
        if self.qmp_server:
            cmd += f"-qmp tcp:localhost:{self.qmp_server.get_server_port()} "
    
        # Misc
        cmd += "-serial stdio "

        return cmd
    
    def is_qemu_installed(self):
        try:
            proc = subprocess.run([self.get_qemu_system_path(), "--version"], capture_output=True)
        except Exception as e:
            output = b''
        else:
            output = proc.stdout
        
        if b'QEMU emulator' not in output:
            return None, "Invalid QEMU binary path"
        
        return None, ""

    def is_online(self):
        if self.qemu_process:
            return self.qemu_process.poll() is None
        return False
    
    def _create_disk(self, force=False):
        profile = ProfileStore.get_vm_profile(self.vm_name)

        if not force and profile.disk_file is not None:
            return None, ""

        try:
            proc = subprocess.run(self.get_create_disk_command())
            self.logger.debug(f"subprocess.run({self.get_create_disk_command()})")
        except Exception as e:
            return None, "Fail to create VM disk"

        # update the VM profile
        if proc.returncode == 0:
            ProfileStore.update_vm_profile(
                self.vm_name,
                disk_file = self.DISK_FILE_NAME
            )

            self.logger.info(f"Disk file was created successfully ({self.DISK_FILE_NAME})")
            return None, ""
        
        return None, "Fail to create VM disk"
    
    def _exit_qemu_process(self):
        if self.qemu_process is not None:
            self.qemu_process.kill()

            outs, errs = self.qemu_process.communicate(timeout=1)
            if errs != b'':
                self.logger.error("QEMU Error output: <br>\n%s" % errs.decode('utf-8'))

            self.qemu_process = None

    def start(self):
        if self.is_online():
            return None, ""

        _, err = self.is_qemu_installed()
        if err:
            return None, err
        
        _, err = self._create_disk()
        if err:
            return None, err
        
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
            return None, "Fail to handshake with QMP server"

        self.qemu_started = True
        self.logger.info("QEMU is started")
        return None, ""
    
    def wait_qemu_start(self, msg=QEMU_START_WAIT_BOX_MESSAGE):
        ida_kernwin.show_wait_box(msg)
        
        res, err = None, ""

        try:
            res, err = self.start()
        except Exception as e:
            err = str(e)
            self.logger.error(e, exc_info=True)
        finally:
            ida_kernwin.hide_wait_box()
        
        return res, err

    def stop(self):
        if not self.is_online():
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

    def wait_qemu_stop(self, msg=QEMU_STOP_WAIT_BOX_MESSAGE):
        ida_kernwin.show_wait_box(msg)
        
        err = ""

        try:
            self.stop()
        except Exception as e:
            err = str(e)
            self.logger.error(e, exc_info=True)
        finally:
            ida_kernwin.hide_wait_box()
        
        return None, err
    
    ##################################################
    #                 QMP Functions                  #
    ##################################################

    def wait_qmp_server_connection(self, msg=QMP_SERVER_WAIT_MESSAGE):
        ida_kernwin.show_wait_box(msg)

        try:
            alive = False
            while True:
                alive = self.qmp_server.execute("query-version")
                if ida_kernwin.user_cancelled() or alive:
                    break
                
                time.sleep(self.IDA_WAIT_TIMEOUT)
        finally:
            ida_kernwin.hide_wait_box()

            return alive, "" if alive else "Fail to connect to QMP"
    
    def wait_qmp_server_job_complete(self, job_id, msg=QMP_SERVER_JOB_WAIT_MESSAGE):
        ida_kernwin.show_wait_box(msg)

        try:
            job_matched = None
            while True:
                res, err = self.qmp_server.execute("query-jobs")

                if not err:
                    for job_info in res:
                        if job_info['id'] == job_id:
                            job_matched = job_info
                            break

                if ida_kernwin.user_cancelled() or \
                    (job_matched and job_matched['status'] == "concluded"):
                    break
                
                time.sleep(self.IDA_WAIT_TIMEOUT)
        finally:
            ida_kernwin.hide_wait_box()

            if job_matched is None or job_matched['status'] != "concluded":
                return None, "Fail to complete job"
            
            return job_matched, ""

    def inject_cdrom(self, iso_file):
        if not self.is_online():
            return None, "VM is offline"
        
        cdrom_file, err = self.qmp_server.request_get_cdrom_file()
        if err or cdrom_file == "":
            return None, "Please retry."

        if os.path.samefile(cdrom_file, iso_file):
            return "ISO image is already inserted", ""
        
        if cdrom_file:
            res, err = self.qmp_server.request_eject()
            if err:
                return res, err
        
        return self.qmp_server.request_insert_cdrom(iso_file)

    def save_snapshot(self, tag):
        if not self.is_online():
            return None, "VM is offline"

        if idaapi.is_debugger_on():
            self.debug_server.invoke_ioctl_save_debmod()
            self.debug_server.invoke_term_debugger()
        
        # Request snapshot-save to QMP
        job_id, err = self.qmp_server.request_save_snapshot(
                tag=tag,
                vmstate=self.BASE_NODE_NAME,
                devices=[self.BASE_NODE_NAME])
        
        if err:
            self.delete_snapshot(tag)
            return None, err

        #if idaapi.is_debugger_on():
        #    self.debug_server.invoke_init_debugger()
        #    self.debug_server.invoke_ioctl_restore_debmod()
        
        # Wait for "snapshot-save" to complete
        job_info, err = self.wait_qmp_server_job_complete(job_id, "Wait for creating snapshot...")
        if err:
            self.delete_snapshot(tag)
            return None, err
        
        if 'error' in job_info:
            self.delete_snapshot(tag)
            return None, job_info['error']
        
        self.qmp_server.request_job_dismiss(job_id)

        return None, ""

    def load_snapshot(self, tag, on_debugging):
        if not self.is_online():
            return None, "VM is offline"

        if idaapi.is_debugger_on():
            ida_dbg.exit_process()

        job_id, err = self.qmp_server.request_load_snapshot(
            tag=tag,
            vmstate=self.BASE_NODE_NAME,
            devices=[self.BASE_NODE_NAME])

        if err:
            return None, err

        # Wait for "snapshot-save" to complete
        job_info, err = self.wait_qmp_server_job_complete(job_id, "Wait for loading snapshot...")

        if err:
            return None, err
        
        if 'error' in job_info:
            return None, job_info['error']
        
        self.qmp_server.request_job_dismiss(job_id)

        return None, ""

        """
        if on_debugging:
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
        """
    
    def delete_snapshot(self, tag):
        if not self.is_online():
            return None, "VM is offline"

        # Request snapshot-delete to QMP
        return self.qmp_server.request_delete_snapshot(
                tag=tag,
                devices=[self.BASE_NODE_NAME])
    
    ##################################################
    #              Debug Agent Functions             #
    ##################################################

    def stop_debug_agent(self):
        if self.is_online():
            self.debug_agent.exec("systemctl stop debug_agent")
            return True
        return False
    
    def restart_debug_agent(self):
        if self.is_online():
            self.debug_agent.exec("systemctl restart debug_agent")
            return True
        return False

    def is_debug_agent_connectable(self):
        if not self.is_online():
            return False

        ida_kernwin.show_wait_box("Connect to the debug agent...")
        try:
            connected = self.debug_agent.is_rpc_server_alive()
        finally:
            ida_kernwin.hide_wait_box()

        self.logger.debug(f"Debug agent connection({connected})")
        return connected
    
    def wait_debug_agent_connection(self, msg=DEBUG_AGENT_WAIT_MESSAGE):
        if not self.is_online():
            return False

        ida_kernwin.show_wait_box(msg)

        try:
            while True:
                connected = self.debug_agent.is_rpc_server_alive()
                if ida_kernwin.user_cancelled() or connected:
                    break
                
                time.sleep(self.IDA_WAIT_TIMEOUT)
        finally:
            ida_kernwin.hide_wait_box()
            return connected
    
    def upload_host_file_to_guest(self, hostfile, guestfile):
        if not self.is_online():
            return None, "QEMU is offline"

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
        
    def start_debuggee_stdout_worker(self):
        self.debug_server.start_stdout_worker()
    
    def stop_debuggee_stdout_worker(self):
        self.debug_server.stop_stdout_worker()

    def send_stdin_to_debuggee(self, data):
        if not self.is_online():
            return None, "QEMU is offline"
        
        return self.debug_server.send_stdin(data)