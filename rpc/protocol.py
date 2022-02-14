from ekko.utils import *

# idasdk76/lib/x64_linux_gcc_64/pro.o/packdd.o
class ByteVector:
    def __init__(self, array=b''):
        self.array = bytearray(array)
        
        # for unpacking
        self.begin = 0
        self.end = len(array)
    
    def pack_db(self, x):
        self.array += p8(x)
    
    def pack_dw(self, x):
        if x < 0x80:
            self.array += p8(x)
        
        elif x < 0x4000:
            self.array += p16(x | 0x8000)
    
        else:
            self.array += b'\xFF' + p16(x)

    def pack_dd(self, x):
        if x < 0x80:
            self.array += p8(x)
        
        elif x < 0x4000:
            self.array += p16(x | 0x8000)
        
        elif x < 0x20000000:
            self.array += p32(x | 0xC0000000)

        else:
            self.array += b'\xFF' + p32(x)
    
    def pack_dq(self, x):
        self.pack_dd(x & 0xFFFFFFFF)
        self.pack_dd(x >> 32)

    def pack_buf(self, buf):
        if type(buf) is str:
            buf = buf.encode('latin-1')
        self.pack_dd(len(buf))
        self.array += buf

    def pack_str(self, str):
        self.array += str.encode('latin-1') + b'\x00'
    
    def unpack_db(self):
        self.begin += 1
        return self.array[self.begin - 1]
    
    def unpack_dw(self):
        i = self.begin

        if self.array[i] & 0x80:
            if self.array[i] & 0xC0 == 0xC0:
                if self.end - 1 <= i:
                    x = 0
                    self.begin += 1
                elif self.end - 2 <= i:
                    x = self.array[i + 1] << 8
                    self.begin += 2
                else:
                    x = ((self.array[i + 1] << 8) | self.array[i + 2])
                    self.begin += 3
            else:
                x = ((self.array[i] << 8) | self.array[i + 1]) & 0x7FFF
                self.begin += 2
        else:
            x = self.unpack_db()
        return x
    
    def unpack_dd(self):
        i = self.begin

        if self.array[i] & 0x80:
            if self.array[i] & 0xC0 == 0xC0:
                if self.array[i] & 0xE0 == 0xE0:
                    if self.end - 1 <= i:
                        x = 0
                        self.begin += 1
                    elif self.end - 2 <= i:
                        x = self.array[i + 1] << 24
                        self.begin += 2
                    elif self.end - 3 <= i:
                        x = ((self.array[i + 1] << 8) | self.array[i + 2]) << 16
                        self.begin += 3
                    else:
                        x = ((self.array[i + 1] << 24) | (self.array[i + 2] << 16) | (self.array[i + 3] << 8) | self.array[i + 4])
                        self.begin += 5
                else:
                    if self.end - 1 <= i:
                        x = 0
                        self.begin += 1
                    elif self.end - 2 <= i:
                        x = ((self.array[i] << 8) | self.array[i + 1]) & 0x3FFF
                        self.begin += 2
                    else:
                        x = ((self.array[i] << 24) | (self.array[i + 1] << 16) | self.array[i + 2] << 8 | self.array[i + 3]) & 0x3FFFFFFF
                        self.begin += 4
            else:
                x = ((self.array[i] << 8) | self.array[i + 1]) & 0x7fff
                self.begin += 2
        else:
            x = self.unpack_db()
        return x
    
    def unpack_dq(self):
        low = self.unpack_dd()
        return low | (self.unpack_dd() << 32)

    def unpack_obj(self, size):
        self.begin += size
        return self.array[self.begin - size: self.begin]

    def unpack_buf(self):
        size = self.unpack_dd()
        if size == 0:
            return b""
        
        self.begin += size
        return self.array[self.begin - size: self.begin]

    def unpack_str(self):
        null_pos = self.array[self.begin:].find(b'\x00')

        if null_pos < 0:
            self.begin = len(self.array)
            return b''

        self.begin += null_pos + 1
        return self.array[self.begin - null_pos - 1: self.begin]

class RPCPacketSerializer(ByteVector):
    def __init__(self):
        super().__init__()
    
    def serialize(self):
        if len(self.array) == 0:
            return b''

        header = (len(self.array) - 1).to_bytes(4, byteorder='little')
        return header + bytes(self.array)

class RPCPacketDeserializer(ByteVector):
    def __init__(self, array):
        super().__init__(array)

# Enums
class DebugEvent:
    ev_init_debugger = 0
    ev_term_debugger = 1
    ev_get_processes = 2
    ev_start_process = 3
    ev_attach_process = 4
    ev_detach_process = 5
    ev_get_debapp_attrs = 6
    ev_rebase_if_required_to = 7
    ev_request_pause = 8
    ev_exit_process = 9
    ev_get_debug_event = 10
    ev_resume = 11
    ev_set_exception_info = 12
    ev_suspended = 13
    ev_thread_suspend = 14
    ev_thread_continue = 15
    ev_set_resume_mode = 16
    ev_read_registers = 17
    ev_write_register = 18
    ev_thread_get_sreg_base = 19
    ev_get_memory_info = 20
    ev_read_memory = 21
    ev_write_memory = 22
    ev_check_bpt = 23
    ev_update_bpts = 24
    ev_update_lowcnds = 25
    ev_open_file = 26
    ev_close_file = 27
    ev_read_file = 28
    ev_write_file = 29
    ev_map_address = 30
    ev_get_debmod_extensions = 31
    ev_update_call_stack = 32
    ev_appcall = 33
    ev_cleanup_appcall = 34
    ev_eval_lowcnd = 35
    ev_send_ioctl = 36
    ev_dbg_enable_trace = 37
    ev_is_tracing_enabled = 38
    ev_rexec = 39
    ev_get_srcinfo_path = 40
    ev_bin_search = 41

class RPCCode:
    RPC_OK = 0
    RPC_UNK = 1
    RPC_MEM = 2
    RPC_OPEN = 3
    RPC_EVENT = 4
    RPC_EVOK = 5
    RPC_CANDELLED = 6
    RPC_INIT = 10
    RPC_TERM = 11
    RPC_GET_PROCESSES = 12
    RPC_START_PROCESS = 13
    RPC_EXIT_PROCESS = 14
    RPC_ATTACH_PROCESS = 15
    RPC_DETACH_PROCESS = 16
    RPC_GET_DEBUG_EVENT = 17
    RPC_PREPARE_TO_PAUSE_PROCESS = 18
    RPC_STOPPED_AT_DEBUG_EVENT = 19
    RPC_CONTINUE_AFTER_EVENT = 20
    RPC_TH_SUSPEND = 21
    RPC_TH_CONTINUE = 22
    RPC_SET_RESUME_MODE = 23
    RPC_GET_MEMORY_INFO = 24
    RPC_READ_MEMORY = 25
    RPC_WRITE_MEMORY = 26
    RPC_UPDATE_BPTS = 27
    RPC_UPDATE_LOWCNDS = 28
    RPC_EVAL_LOWCND = 29
    RPC_ISOK_BPT = 30
    RPC_READ_REGS = 31
    RPC_WRITE_REG = 32
    RPC_GET_SREG_BASE = 33
    RPC_SET_EXCEPTION_INFO = 34
    RPC_OPEN_FILE = 35
    RPC_CLOSE_FILE = 36
    RPC_READ_FILE = 37
    RPC_WRITE_FILE = 38
    RPC_IOCTL = 39
    RPC_UPDATE_CALL_STACK = 40
    RPC_APPCALL = 41
    RPC_CLEANUP_APPCALL = 42
    RPC_REXEC = 43
    RPC_GET_SCATTERED_IMAGE = 44
    RPC_GET_IMAGE_UUID = 45
    RPC_GET_SEGM_START = 46
    RPC_BIN_SEARCH = 47

class IOCTL:
    PREPARE_SNAPSHOT = 100
    FINISH_SNAPSHOT = 101