from cmath import log
import json
import socket
import select
import logging
import traceback

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
        self.server = None
        self.client = None
        self.port = None

    def get_server_port(self):
        return self.port
    
    def listen(self):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.TIMEOUT_DEFAULT)

        self.port = get_avaliable_port()
        sock.bind(('localhost', self.port))
        sock.listen()

        self.server = sock

    def handshake(self):
        success = False

        # Accept the QEMU client
        try:
            self.client, _  = self.server.accept()
            self.client.settimeout(self.TIMEOUT_DEFAULT)

            logging.info("QMP client accepted")

            # Recieve the banner message
            banner = self._recv()
            if 'QMP' not in banner:
                return False
            
            logging.info("Recieved handshake message from QMP client")
            
            success, _ = self._execute("qmp_capabilities")
        except Exception as e:
            traceback.print_exc()
            pass
        
        if success == False:
            logging.error("Fail to handshake with QMP client")

        return success

    def close(self):
        self.server.close()
        if self.client is not None:
            self.client.close()
            self.client = None
    
    def _send(self, data):
        assert self.client, "QMP is not connected"

        self.client.send(json.dumps(data).encode())

    def _recv(self):
        assert self.client, "QMP is not connected"

        readable, _, _ = select.select([self.client], [], [], self.TIMEOUT_RECV)
        assert readable, "QMP is not readable"
        
        data = b''
        while True: # Todo: make more concrete
            data += self.client.recv(1024)
            if data.endswith(b'\n'):
                success, res = parse_qmp_response(data)
                if success:
                    return res

    def _execute(self, cmd, arguments=None):
        logging.debug(f"qmp.execute({cmd})")

        data = {"execute": cmd}
        if arguments:
            data["arguments"] = arguments

        try:
            self._send(data)
        
            res = self._recv()
        except Exception as e:
            return False, str(e)

        if 'error' in res:
            return False, res['error']
        elif 'return' in res:
            return True, res['return']
        else:
            return True, res


    def request_exit(self):
        self._execute("quit")
    
    def get_cdrom_file(self):
        success, res = self._execute("query-block")
        if not success:
            logging.error(res)
            return False, ''
        
        for dev_info in res:
            if type(dev_info) is not dict:
                continue

            if dev_info['device'] != 'ide1-cd0':
                continue
            
            if 'inserted' not in dev_info:
                return False, ''
            
            return True, dev_info['inserted']['file']
        
        logging.error("CD-ROM(ide1-cd0) not found")
        return False, ''
        
    def request_eject(self):
        success, res = self._execute("eject", arguments = {"device":"ide1-cd0", "force":True})

        if not success:
            logging.error(res)
            return False, "Fail to eject CD-ROM"
        
        logging.info("CD-ROM is ejected")
        return True, ''
    
    def request_insert_cdrom(self, iso_file):
        success, res = self._execute(
            "blockdev-change-medium",
            arguments = {
                "device" : "ide1-cd0",
                "filename" : iso_file,
                "format": "raw"
            }
        )

        if not success:
            logging.error(res)
            return False, f"Fail to insert CD-ROM({iso_file})"
        
        logging.info(f"CD-ROM is inserted ({iso_file})")
        return True, ''