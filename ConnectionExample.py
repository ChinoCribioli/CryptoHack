import socket
import json

HOST = "socket.cryptohack.org"
PORT = 13403 

from pwn import * # pip install pwntools
import json

r = remote(HOST, PORT)

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(message):
    request = json.dumps(message).encode()
    r.sendline(request)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(10000), "\n")

    response = socket.recv(10000)
    q = int(response.split(b'"')[1], 16)
    n = q**2 
    phi_n = q*(q-1)
    g = pow(2,q-1,n)

    params = {
        'g': hex(g),
        'n': hex(n)
    }
    socket.send(json.dumps(params).encode('utf-8'))

    print(socket.recv(10000), "\n")

    answer = {
        'x': hex(secret)
    }
    socket.send(json.dumps(answer).encode('utf-8'))

    print(socket.recv(10000), "\n")

