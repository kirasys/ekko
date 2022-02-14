import json
import socket
import select
import logging

from ekko.utils import *
    
class QMPSocketServer:
    TIMEOUT_DEFAULT = 5

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
            if b'QMP' not in banner:
                return False
            
            self.logger.info("Recieved handshake message from QMP client")
            
            _, err = self.execute("qmp_capabilities")
        except Exception as e:
            err = str(e)
            self.logger.error(e, exc_info=True)

        if err:
            self.logger.error(f"Fail to handshake with QMP client({err})")

        return len(err) == 0

    def close(self):
        self.server.close()
        if self.client is not None:
            self.client.close()
            self.client = None
    
    def _send(self, data):
        assert self.client, "QMP is offline"

        self.client.send(data)

    def _recv(self):
        assert self.client, "QMP is offline"

        readable, _, _ = select.select([self.client], [], [], self.TIMEOUT_DEFAULT)
        if not readable:
            return b"{}"
        
        data = b''
        while True: # Todo: make more concrete
            data += self.client.recv(4096)
            print("_recv:",data)
            if data.endswith(b'\n'):
                _, err = parse_qmp_response(data)
                if not err:
                    return data
    
    def _send_json(self, data):
        self._send(json.dumps(data).encode())

    def _recv_json(self, id):
        while True:
            res, _ = parse_qmp_response(self._recv())

            # match command id
            if 'id' in res and res['id'] == id:
                return res

    def flush_recv(self, timeout=0):
        while True:
            readable, _, _ = select.select([self.client], [], [], timeout)
            if not readable:
                break

            self._recv_json()

    def execute(self, cmd, arguments=None):
        self.logger.debug(f"qmp.execute({cmd})")
        
        data = {"execute": cmd}
        if arguments:
            data["arguments"] = arguments

        cmd_id = generate_random_hexstring()
        data['id'] = cmd_id

        print(f"execute({cmd_id}) :",cmd, data)
        try:
            self._send_json(data)
        
            res = self._recv_json(cmd_id)
        except Exception as e:
            self.logger.error(e, exc_info=True)
            return None, str(e)
        
        print(f"execute({cmd_id}) :", res,'\n')
        if 'error' in res:
            return res, f"Fail to execute {cmd}"
        elif 'return' in res:
            return res['return'], ""
        else:
            return res, ""

    def request_exit(self):
        self.execute("quit")

    def request_job_dismiss(self, job_id):
        return self.execute("job-dismiss",
            arguments = {'id' : job_id}
        )
    
    def request_get_cdrom_file(self):
        res, err = self.execute("query-block")
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
        res, err = self.execute("eject", arguments = {"device":"ide1-cd0", "force":True})

        if err:
            self.logger.error(err)
            return None, err
        
        self.logger.info("CD-ROM is ejected")
        return res, ""
    
    def request_insert_cdrom(self, iso_file):
        res, err = self.execute(
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
        res, err = self.execute("query-block")
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
        res, err = self.execute(
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
        res, err = self.execute(
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
        res, err = self.execute(
            "human-monitor-command",
            arguments = {
                'command-line': f"delvm {tag}"
            }
        )
        if err:
            self.logger.error(err)
            return None, err
        
        return res, ""
    
    def request_save_snapshot(self, tag, vmstate, devices):
        job_id = generate_random_hexstring()

        _, err = self.execute(
            "snapshot-save",
            arguments = {
                'job-id' : job_id,
                'tag' : tag,
                'vmstate' : vmstate,
                'devices' : devices
            }
        )

        return job_id, err
    
    def request_load_snapshot(self, tag, vmstate, devices):
        job_id = generate_random_hexstring()

        _, err = self.execute(
            "snapshot-load",
            arguments = {
                'job-id' : job_id,
                'tag' : tag,
                'vmstate' : vmstate,
                'devices' : devices
            }
        )

        return job_id, err

    def request_delete_snapshot(self, tag, devices):
        job_id = generate_random_hexstring()

        _, err = self.execute(
            "snapshot-delete",
            arguments = {
                'job-id' : job_id,
                'tag' : tag,
                'devices' : devices
            }
        )

        return job_id, err

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
    
    return json_parsed, "" if brace_count == 0 else "Invalid json format"