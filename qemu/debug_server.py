import idc
import time
import ctypes
import select
import socket
import logging
import traceback
import threading

from ekko.rpc.client import RPCClient
from ekko.rpc.protocol import DebugEvent
from ekko.utils import *

class DebugServerClient(RPCClient):
    PORT = 40001
    STDOUT_RECV_TIMEOUT = 5

    def __init__(self, vm_name):
        super().__init__()
        self.vm_name = vm_name
        self.logger = logging.getLogger(vm_name)
        self.debug_output_logger = logging.getLogger(f"{vm_name}_debug_output")

        self.stdin_fwd_port = get_avaliable_port()
        self.stdout_fwd_port = get_avaliable_port()
        self.stdin_sock = None
        self.stdout_sock = None
        self.stdout_data = b''
        self.server_connected = False
        
        self.lock = threading.Lock()
        self.recv_worker = threading.Timer(1, self.recv_output_worker)
        self.logging_worker = threading.Timer(1, self.logging_output_worker)
        self.recv_worker.start()
        self.logging_worker.start()

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

    def recv_output_worker(self):
        while True:
            try:
                if not self.__connect_stdin() or not self.__connect_stdout():
                    continue
                
                readable, _, _ = select.select([self.stdout_sock], [], [], self.STDOUT_RECV_TIMEOUT)
                if not readable:
                    continue
            except socket.timeout:
                continue
            except Exception as e:
                print(str(e))
                traceback.print_exc()
                self.close()
                return
            
            try:
                self.lock.acquire()
                data = self.stdout_sock.recv(1024)
                if data != b'':
                    self.stdout_data += data
                self.lock.release()

            except Exception as e:
                print(str(e))
                traceback.print_exc()
                self.close()

                if self.lock.locked():
                    self.lock.release()

                return

    def logging_output_worker(self):
        while True:
            if self.stdout_data:
                self.lock.acquire()
                self.debug_output_logger.debug(self.stdout_data.decode('utf-8'))
                self.stdout_data = b''
                self.lock.release()

            time.sleep(0.3)

    def __connect_stdin(self):
        if self.stdin_sock:
            return True

        self.stdin_sock = self._connect(self.stdin_fwd_port)
        return self.stdin_sock is not None
    
    def __connect_stdout(self):
        if self.stdout_sock:
            return True

        self.stdout_sock = self._connect(self.stdout_fwd_port)
        return self.stdout_sock is not None

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

    def send_input(self, data):
        if not self.__connect_stdin():
            return None, "Remote RPC Server is not connected!"
        
        try:
            self.debug_output_logger.debug(data)
            self.stdin_sock.send(data.encode('utf-8'))
        except Exception:
            return None, "Socket error"
        
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
        IOCTL_SAVE_DEBMOD = 100
        self._invoke_callbacks(DebugEvent.ev_send_ioctl,
            IOCTL_SAVE_DEBMOD,
            ctypes.c_char_p(b'a'*8),
            1,
            0,
            0
        )
    
    def invoke_ioctl_restore_debmod(self):
        IOCTL_RESTORE_DEBMOD = 101
        self._invoke_callbacks(DebugEvent.ev_send_ioctl,
            IOCTL_RESTORE_DEBMOD,
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
        
