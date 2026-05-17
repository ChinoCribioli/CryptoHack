import socket as sckt
import json
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13390 

def json_recv(socket):
    line = b''
    while True:
        try:
            line += socket.recv(100000)
            return json.loads(line)
        except:
            pass

def json_send(socket, message):
    request = json.dumps(message).encode()
    socket.send(request)


with sckt.socket(sckt.AF_INET, sckt.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(10000))


