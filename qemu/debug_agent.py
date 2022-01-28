import socket
import select

from ekko.rpc.client import RPCClient
from ekko.rpc.protocol import RPCCode

def rpc_request(func):
    def wrapper(self, *args, **kwargs):
        if not self.handshake():
            return False, "Fail to handshake with the RPC server"
        return func(self, *args, **kwargs)
    return wrapper

class DebugAgentClient(RPCClient):
    PORT = 40000

    def __init__(self, vm_name):
        super().__init__()
        self.vm_name = vm_name
    
    def close(self):
        self._close()
    
    def get_port(self):
        return self.PORT
    
    def get_fwd_port(self):
        return self.host_fwd_port

    @rpc_request
    def open_file(self, filename, readonly):
        req = self.prepare_rpc_packet(RPCCode.RPC_OPEN_FILE)
        req.pack_str(filename)
        req.pack_dd(readonly)
        
        res = self._send_packet_and_receive_reply(req)
        if res is None:
            return False, "Fail to send RPC_OPEN_FILE"
        
        fn = res.unpack_dd()
        if fn != -1:
            if readonly:
                return {'fn': fn, 'fsize': res.unpack_dq()}, ""
            else:
                return {'fn': fn, 'fsize': 0}, ""

        return False, f"Fail to open {filename}"

    @rpc_request
    def close_file(self, fn):
        req = self.prepare_rpc_packet(RPCCode.RPC_CLOSE_FILE)
        req.pack_dd(fn)

        res = self._send_packet_and_receive_reply(req)
        if res is None:
            return False, "Fail to send RPC_WRITE_FILE"
        return True, ""
    
    @rpc_request
    def read_file(self, fn, off, size):
        req = self.prepare_rpc_packet(RPCCode.RPC_READ_FILE)
        req.pack_dd(fn)
        req.pack_dd(off)
        req.pack_dd(size & 0xFFFFFFFF)

        res = self._send_packet_and_receive_reply(req)
        if res is None:
            return False, "Fail to send RPC_READ_FILE"
        
        rsize = res.unpack_dd()
        if rsize != size:
            return False, f"Fail to read the file({fn})"
        
        return {'rsize': rsize, 'buf': res.unpack_obj(rsize)}, ""

    @rpc_request
    def write_file(self, fn, off, buf, size):
        req = self.prepare_rpc_packet(RPCCode.RPC_WRITE_FILE)
        req.pack_dd(fn)
        req.pack_dq(off)
        req.pack_buf(buf)

        res = self._send_packet_and_receive_reply(req)
        if res is None:
            return False, "Fail to send RPC_WRITE_FILE"
        
        rsize = res.unpack_dd()
        if rsize != size:
            return False, f"Fail to write the file({fn})"

        return {'rsize': rsize}, ""
    
    @rpc_request
    def exec(self, cmd):
        req = self.prepare_rpc_packet(RPCCode.RPC_REXEC)
        req.pack_str(cmd)

        res = self._send_packet_and_receive_reply(req)
        if res is None:
            return False, "Fail to send RPC_REXEC"
        
        return {'return_code': res.unpack_dd()}, ""