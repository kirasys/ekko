import json
import socket
import select
import logging
import traceback

from ekko.utils import *

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

    def __init__(self, vm_name):
        self.vm_name = vm_name
        self.logger = logging.getLogger(vm_name)
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
        err = ''

        # Accept the QEMU client
        try:
            self.client, _  = self.server.accept()
            self.client.settimeout(self.TIMEOUT_DEFAULT)

            self.logger.info("QMP client accepted")

            # Recieve the banner message
            banner = self._recv()
            if 'QMP' not in banner:
                return False
            
            self.logger.info("Recieved handshake message from QMP client")
            
            _, err = self._execute("qmp_capabilities")
        except Exception as e:
            traceback.print_exc()
            err = str(e)
        
        if err:
            self.logger.error(f"Fail to handshake with QMP client({err})")

        return len(err) == 0

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
    
    def health_check(self):
        _, err = self._execute("query-version")
        return len(err) == 0 

    def _execute(self, cmd, arguments=None):
        self.logger.debug(f"qmp.execute({cmd})")

        data = {"execute": cmd}
        if arguments:
            data["arguments"] = arguments

        try:
            self._send(data)
        
            res = self._recv()
        except Exception as e:
            return None, str(e)
        print(res)
        if 'error' in res:
            return None, f"Fail to execute {cmd}"
        elif 'return' in res:
            return res['return'], ""
        else:
            return res, ""

    def request_exit(self):
        self._execute("quit")
    
    def get_cdrom_file(self):
        res, err = self._execute("query-block")
        if err:
            self.logger.error(err)
            return None, err
        
        for dev_info in res:
            if type(dev_info) is not dict:
                continue

            if dev_info['device'] != 'ide1-cd0':
                continue
            
            if 'inserted' not in dev_info:
                return None, 'Could not find any medium device'
            
            return dev_info['inserted']['file'], ""
        
        err = "CD-ROM(ide1-cd0) not found"
        self.logger.error(err)
        return None, err
        
    def request_eject(self):
        res, err = self._execute("eject", arguments = {"device":"ide1-cd0", "force":True})

        if err:
            self.logger.error(err)
            return None, err
        
        self.logger.info("CD-ROM is ejected")
        return res, ""
    
    def request_insert_cdrom(self, iso_file):
        res, err = self._execute(
            'blockdev-change-medium',
            arguments = {
                'device' : 'ide1-cd0',
                'filename' : iso_file,
                'format': 'raw'
            }
        )

        if err:
            self.logger.error(err)
            return None, f"Fail to insert CD-ROM({iso_file})"
        
        self.logger.info(f"CD-ROM is inserted ({iso_file})")
        return res, ""
    
    def request_get_snapshots_info(self, device):
        res, err = self._execute("query-block")
        if err:
            self.logger.error(err)
            return None, err
        
        for dev_info in res:
            if type(dev_info) is not dict:
                continue

            if dev_info['device'] != device:
                continue
            
            if 'inserted' not in dev_info or \
                'image' not in dev_info['inserted']:
                return None, "Could not find disk device"
            
            if 'snapshots' not in dev_info['inserted']['image']:
                return [], ""
            
            return dev_info['inserted']['image']['snapshots'], ""

        err = f"Disk({device}) not found"
        self.logger.error(err)
        return None, err

    def request_save_snapshot_hm(self, tag):
        res, err = self._execute(
            "human-monitor-command",
            arguments = {
                'command-line': f"savevm {tag}"
            }
        )

        if err:
            self.logger.error(err)
            return None, err
        
        return res, ""

    def request_load_snapshot_hm(self, tag):
        res, err = self._execute(
            "human-monitor-command",
            arguments = {
                'command-line': f"loadvm {tag}"
            }
        )
        if err:
            self.logger.error(err)
            return None, err
        
        return res, ""
    
    def request_delete_snapshot_hm(self, tag):
        res, err = self._execute(
            "human-monitor-command",
            arguments = {
                'command-line': f"delvm {tag}"
            }
        )
        if err:
            self.logger.error(err)
            return None, err
        
        return res, ""
    
    def request_save_snapshot(self, job_id, tag, vmstate, devices):
        res, err = self._execute(
            "snapshot-save",
            arguments = {
                'job-id' : job_id,
                'tag' : tag,
                'vmstate' : vmstate,
                'devices' : devices
            }
        )
        if err:
            self.logger.error(err)
            return None, err
        
        return res, ""