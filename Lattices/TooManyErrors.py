### SOURCE

from Crypto.Random.random import getrandbits
import random
# from utils import listener

SEED = getrandbits(32)
FLAG = b'crypto{????????????????????}'
q = 127


class Challenge():
    def __init__(self):
        self.before_input = f"Welcome to the LWE sample generator! Retrieve a sample using the 'get_sample' option, or reset the distribution using the 'reset' option.\n"
        self.rand = random.Random(SEED)

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input["option"] == "reset":
            self.rand.seed(SEED)
            return {"success": "The distribution has been reset"}

        elif your_input["option"] == "get_sample":
            a = []
            for i in range(len(FLAG)):
                a.append(self.rand.randint(0, q - 1))

            e = self.rand.randint(-1, 1)

            self.rand.seed(getrandbits(32))
            if self.rand.randint(0, 1):
                a[self.rand.randint(0, len(a) - 1)] = self.rand.randint(0, q - 1)

            b = 0
            for (i, j) in zip(a, FLAG):
                b += i * j
            b += e
            b %= q

            return {"a": a, "b": b}

        else:
            return {"error": "Invalid option"}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
# listener.start_server(port=13390)

### SOLUTION

import socket as sckt
import json
import ast
import numpy as np
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13390 

r = remote(HOST, PORT)

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
    
    print(socket.recv(20000), "\n")

    # First, we get the unchanged a and b, that we will take as reference.
    ref_a, ref_b = [], -1
    a_candidates, b_candidates = [], []
    T = 8 # Number of samples we take to find the reference a and b
    for t in range(T):
        message = {
            'option': 'get_sample',
        }
        json_send(socket, message)
        response = json_recv(socket)
        a_candidates.append(response['a'])
        b_candidates.append(response['b'])

        message = {
            'option': 'reset',
        }
        json_send(socket, message)
        response = json_recv(socket)

    for i in range(T):
        if len(ref_a):
            break
        for j in range(i+1,T):
            if a_candidates[i] == a_candidates[j]:
                ref_a, ref_b = a_candidates[i], b_candidates[i]
                break
    print("Found the unchanged a and b!")

    assert(ref_a == [68, 111, 104, 46, 12, 48, 29, 77, 113, 31, 76, 80, 126, 24, 77, 34, 69, 119, 109, 36, 85, 69, 28, 117, 80, 57, 110, 95])
    assert(ref_b == 1)

    # Now, we make queries until we complete the flag by encountering different values at the a's.
    l = len(ref_a)
    found_characters = 0
    flag = [0]*l
    while found_characters < l:
        message = {
            'option': 'reset',
        }
        json_send(socket, message)
        response = json_recv(socket)

        message = {
            'option': 'get_sample',
        }
        json_send(socket, message)
        response = json_recv(socket)
        a, b = response['a'], response['b']
        if a == ref_a:
            continue

        index = -1
        for i in range(l):
            if a[i] != ref_a[i]:
                index = i 
                break
        if flag[index] != 0:
            continue

        flag[index] = ( (ref_b - b) * pow(ref_a[index] - a[index], -1, q) ) % q
        found_characters += 1
        print(bytes(flag))



    
