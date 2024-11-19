# Challenge from the "Encoding" section of https://cryptohack.org/challenges/general/ 

from pwn import * # pip install pwntools
import json
import base64
import codecs

r = remote('socket.cryptohack.org', 13377)#, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

for _ in range(100):
    received = json_recv()

    decoded = ""
    if received["type"] == "base64":
        decoded = base64.b64decode(received["encoded"])
    elif received["type"] == "hex":
        decoded = bytes.fromhex(received["encoded"])
    elif received["type"] == "rot13":
        decoded = codecs.decode(received["encoded"], 'rot_13').encode()
    elif received["type"] == "bigint":
        decoded = bytes.fromhex(received["encoded"][2:])
    elif received["type"] == "utf-8":
        decoded = bytes(received["encoded"])

    to_send = {
        "decoded": decoded.decode("utf-8")
    }
    json_send(to_send)


print(json_recv())