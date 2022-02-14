import idc
import time
import ctypes
import select
import socket
import logging
import traceback
import threading

from ekko.rpc.client import RPCClient
from ekko.rpc.protocol import DebugEvent, IOCTL
from ekko.store.stdio import StdioStore
from ekko.utils import *

class DebugServerClient(RPCClient):
    PORT = 40001
    STDOUT_RECV_TIMEOUT = 3

    def __init__(self, vm_name):
        super().__init__()
        self.vm_name = vm_name
        self.logger = logging.getLogger(vm_name)

        self.stdin_fwd_port = get_avaliable_port()
        self.stdout_fwd_port = get_avaliable_port()
        self.stdin_sock = None
        self.stdout_sock = None
        
        self.stdout_worker_activated = False
        self.stdout_worker_handle = None

        idaname = "ida64" if idc.__EA64__ else "ida"
        self.ida_dll = ctypes.windll[f"{idaname}.dll"]

    def get_port(self):
        return self.PORT
    
    def get_fwd_port(self):
        return self.host_fwd_port
    
    def get_stdin_fwd_port(self):
        return self.stdin_fwd_port

    def get_stdout_fwd_port(self):
        return self.stdout_fwd_port

    def _connect_stdin(self):
        if self.stdin_sock:
            return True

        self.stdin_sock = self._connect(self.stdin_fwd_port)
        return self.stdin_sock is not None
    
    def _connect_stdout(self):
        if self.stdout_sock:
            return True

        self.stdout_sock = self._connect(self.stdout_fwd_port)
        return self.stdout_sock is not None

    def is_stdout_worker_activated(self):
        return self.stdout_worker_activated

    def start_stdout_worker(self):
        if self.is_stdout_worker_activated():
            return
            
        self.stdout_worker_activated = True
        self.stdout_worker_handle = threading.Thread(target=self._stdout_worker)
        self.stdout_worker_handle.start()
    
    def stop_stdout_worker(self):
        if not self.is_stdout_worker_activated():
            return

        self.stdout_worker_activated = False
        self.stdout_worker_handle.join()

    def _stdout_worker(self):
        while self.is_stdout_worker_activated():
            if not self._connect_stdout():
                continue
            
            readable, _, _ = select.select([self.stdout_sock], [], [], self.STDOUT_RECV_TIMEOUT)
            if not readable:
                continue
            
            output = self.stdout_sock.recv(1024)
            if output != b'':
                StdioStore.update_stdio_data(self.vm_name, output)
            
    """
    def recv_output(self, size):
        self.lock.acquire()
        if len(self.stdout_data) < size:
            size = len(self.stdout_data)

        data = self.stdout_data[:size]
        self.debug_output_logger.debug(data.decode('utf-8'))

        self.stdout_data = self.stdout_data[size:]
        self.lock.release()
        return data

    def recv_all_output(self):
        return self.recv_output(len(self.stdout_data))
    """

    def send_stdin(self, data):
        if not self._connect_stdin():
            return None, "Remote RPC Server is not connected!"
        
        try:
            self.stdin_sock.send(data)
        except Exception:
            return None, "Socket error"
        
        StdioStore.update_stdio_data(self.vm_name, data)

        return None, ""
    
    def _invoke_callbacks(self, event_code, *args):
        HT_IDD = 8
        c_args = (ctypes.c_char_p * len(args))(*args)
        self.ida_dll.invoke_callbacks(HT_IDD, event_code, c_args)

    def invoke_init_debugger(self):
        self._invoke_callbacks(DebugEvent.ev_init_debugger,
            ctypes.c_char_p(b'127.0.0.1'),
            self.host_fwd_port,
            ctypes.c_char_p(b''),
            ctypes.c_char_p(b'0'*100),
        )
    
    def invoke_term_debugger(self):
        self._invoke_callbacks(DebugEvent.ev_term_debugger)

    def invoke_ioctl_save_debmod(self):
        self._invoke_callbacks(DebugEvent.ev_send_ioctl,
            IOCTL.PREPARE_SNAPSHOT,
            ctypes.c_char_p(b'a'*8),
            1,
            0,
            0
        )
    
    def invoke_ioctl_restore_debmod(self):
        self._invoke_callbacks(DebugEvent.ev_send_ioctl,
            IOCTL.FINISH_SNAPSHOT,
            ctypes.c_char_p(b'a'*8),
            1,
            0,
            0
        )

    def close(self):
        self._close()

        if self.stdin_sock:
            self.stdin_sock.close()
            self.stdin_sock = None
        
        if self.stdout_sock:
            self.stdout_sock.close()
            self.stdout_sock = None
        
        self.stdout_worker_activated = False
        
