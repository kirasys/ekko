import socket
import select
import logging

from ekko.rpc.protocol import *

class RPCClient:
    DEFAULT_TIMEOUT = 4
    TIMEOUT_RECV = 3

    def __init__(self):
        self.host_fwd_port = get_avaliable_port()
        self.rpc_sock = None
        self.is_handshaked = False
    
    def get_host_forward_port(self):
        return self.host_fwd_port

    def is_rpc_server_alive(self):
        res = ''

        if self.rpc_sock:
            self.rpc_sock.send(b'\x00\x00\x00\x01\x01\x00')
            try:
                res = self.rpc_sock.recv(1024)
                if len(res) > 0:
                    return True
            except socket.timeout:
                self._close()

        sock = socket.socket()
        sock.settimeout(3)
        if sock.connect_ex(('127.0.0.1', self.host_fwd_port)):
            return False

        try:
            res = sock.recv(1024)
        except socket.timeout:
            pass
        
        sock.close()
        return len(res) > 0

    def _connect(self, port):
        sock = socket.socket()
        if sock.connect_ex(('127.0.0.1', port)):
            print(f"_connect: fail to connect to the port({port})")
            return None
        
        sock.settimeout(self.DEFAULT_TIMEOUT)
        return sock
    
    def _connect_rpc_server(self):
        self.rpc_sock = self._connect(self.host_fwd_port)
        return self.rpc_sock is not None
    
    def _close(self):
        if self.rpc_sock:
            self.rpc_sock.close()
            self.rpc_sock = None
        self.is_handshaked = False
    
    def _send_packet(self, packet: RPCPacketSerializer):
        try:
            assert self.rpc_sock, "Agent is not connected"
            
            if len(packet.array) == 0:
                return False

            length = (len(packet.array) - 1).to_bytes(4, byteorder='big')
            self.rpc_sock.send(length + bytes(packet.array))
            return True
        except Exception as e:
            print(f"_send_packet: {e}")
            return False

    def _recv_packet(self):
        try:
            assert self.rpc_sock, "Agent is not connected"

            readable, _, _ = select.select([self.rpc_sock], [], [], self.TIMEOUT_RECV)
            assert readable, "Agent is not readable"

            length = int.from_bytes(self.rpc_sock.recv(4), "big") + 1
            
            alldata = b''
            while len(alldata) < length:
                data = self.rpc_sock.recv(length - len(alldata))
                assert data != b'', "Remote RPC server is disconnected"

                alldata += data

            assert len(alldata) != 0, "Remote RPC server is disconnected"
            return RPCPacketDeserializer(alldata)
        except Exception as e:
            print(f"_recv_packet: {e}")
            return None
    
    def _send_packet_and_receive_reply(self, packet: RPCPacketSerializer):
        success = self._send_packet(packet)
        if not success:
            self._close()
            return None
            
        res = self._recv_packet()
        if res is None:
            self._close()
            return None
        
        if res.unpack_dd() != RPCCode.RPC_OK:
            print(f"Unknown RPCCode({code}). Expect RPC_OK")
            self._close()
            return None
        
        return res

    def handshake(self):
        if self.is_handshaked:
            return True

        # Recieve RPC_OPEN from Guest
        res = None
        
        if self._connect_rpc_server():
            res = self._recv_packet()

        if res is None:
            self._close()
            return False

        code    = res.unpack_dd()
        version = res.unpack_dd()
        easize  = res.unpack_dd()

        if code != RPCCode.RPC_OPEN:
            print(f"Unknown RPCCode({code}). Expect RPC_OPEN")
            self._close()
            return False
        
        # Send RPC_OK to the guest and receive an reply
        req = self.prepare_rpc_packet(RPCCode.RPC_OK)
        req.pack_dd(True)
        req.pack_str("")
        
        res = self._send_packet_and_receive_reply(req)
        if res is None:
            self._close()
            return False

        self.is_handshaked = True
        return True
    
    @staticmethod
    def prepare_rpc_packet(code):
        req = RPCPacketSerializer()
        req.pack_dd(code)
        return req
