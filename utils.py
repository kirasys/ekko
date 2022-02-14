import socket
import random
import ida_loader

p8  = lambda x: x.to_bytes(1, byteorder='big')
p16 = lambda x: x.to_bytes(2, byteorder='big')
p32 = lambda x: x.to_bytes(4, byteorder='big')

def get_avaliable_port():
    sock = socket.socket()
    sock.bind(('', 0))
    return sock.getsockname()[1]

def unix_path_join(*args):
    return '/'.join(args)

def get_loaded_binary_path():
    return ida_loader.get_path(0)

def generate_random_hexstring(length=16):
    jobid = random.choice('abcdef')
    for _ in range(length - 1):
        jobid += random.choice('0123456789abcdef')
    return jobid