import socket

def get_avaliable_port():
    sock = socket.socket()
    sock.bind(('', 0))
    return sock.getsockname()[1]

class DebugAgentClient:
    AGENT_GUEST_PORT = 40000

    def __init__(self):
        self.host_port = get_avaliable_port()
    
    def get_host_port(self):
        return self.host_port
    
    def get_guest_port(self):
        return self.AGENT_GUEST_PORT
    
    def is_connected(self):
        sock = socket.socket()
        if sock.connect_ex(('127.0.0.1', self.host_port)):
            return False
        
        sock.settimeout(3)
        try:
            res = sock.recv(1024)
        except socket.timeout:
            res = ''
        
        sock.close()
        return len(res) > 0