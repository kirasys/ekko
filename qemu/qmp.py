import json
import socket
import select

def get_avaliable_port():
    sock = socket.socket()
    sock.bind(('', 0))
    return sock.getsockname()[1]

def parse_qmp_response(json_str):
    json_parsed = {}

    json_start_index = 0
    brace_count = 0
    is_string = False
    for i in range(len(json_str)): 
        if json_str[i] == ord('"') and json_str[i-1] != ord('\\'):
            is_string = not is_string

        if json_str[i] == ord('{') and not is_string:
            if brace_count == 0:
                json_start_index = i

            brace_count += 1
                
        if json_str[i] == ord('}') and not is_string:
            brace_count -= 1

            if brace_count == 0:
                json_parsed.update(json.loads(json_str[json_start_index:i+1]))
    
    return brace_count == 0, json_parsed

class QMPSocketServer:
    TIMEOUT_DEFAULT = 5
    TIMEOUT_RECV = 3

    def __init__(self):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.TIMEOUT_DEFAULT)

        self.port = get_avaliable_port()
        sock.bind(('localhost', self.port))
        sock.listen()

        self.server = sock
        self.client = None

    def get_server_port(self):
        return self.port

    def handshake(self):
        # Accept the QEMU client
        self.client, _  = self.server.accept()
        self.client.settimeout(self.TIMEOUT_DEFAULT)

        # Recieve the banner message
        banner = self._recv()
        if 'QMP' not in banner:
            return False
        
        success, _ = self.execute("qmp_capabilities")
        return success

    def close(self):
        self.server.close()
        if self.client is not None:
            self.client.close()
            self.client = None
    
    def execute(self, cmd):
        self._send({
            "execute": cmd
        })
        
        res = self._recv()

        if 'error' in res:
            return False, res['error']
        elif 'return' in res:
            return True, res['return']
        else:
            return False, res

    def _send(self, data):
        assert self.client, "QMP is not connected"

        self.client.send(json.dumps(data).encode())

    def _recv(self):
        assert self.client, "QMP is not connected"

        readable, _, _ = select.select([self.client], [], [], self.TIMEOUT_RECV)
        assert readable, "No respond (QMP)"
        
        data = b''
        while True: # Todo: make more concrete
            data += self.client.recv(1024)
            if data.endswith(b'\n'):
                success, res = parse_qmp_response(data)
                if success:
                    return res

            