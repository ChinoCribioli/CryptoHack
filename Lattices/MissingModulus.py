### SOURCE

#!/usr/bin/env python3

# from utils import listener
import numpy as np
from random import SystemRandom


FLAG = b'crypto{??????????????????????????????????????}'

random = SystemRandom()

# dimension
n = 512
# plaintext modulus
p = 257
# ciphertext modulus
q = 6007
# message scaling factor
delta = int(round(q/p)) # delta = 23

sigma = 3.8
normal = lambda: round(random.gauss(0, sigma))
uniform = lambda: random.randrange(q) - q//2
dtype = np.int64

def sample(shape, dist):
    return np.fromfunction(np.vectorize(lambda *_: dist()), shape).astype(dtype)

S = sample((n,), uniform)

def encrypt(m):
    A = sample((n,), uniform)
    e = sample((1,), normal)[0]
    b = A @ S + m * delta + e
    return A.tolist(), b.tolist()


class Challenge:
    def __init__(self):
        self.before_input = "Would you like to encrypt your own message, or see an encryption of a character in the flag?\n"

    def challenge(self, your_input):
        if 'option' not in your_input:
            return {'error': 'You must specify an option'}

        if your_input['option'] == 'get_flag':
            if "index" not in your_input:
                return {"error": "You must provide an index"}
                self.exit = True

            index = int(your_input["index"])
            if index < 0 or index >= len(FLAG) :
                return {"error": f"index must be between 0 and {len(FLAG) - 1}"}
                self.exit = True

            A, b = encrypt(FLAG[index])
            return {"A": str(list(A)), "b": str(int(b))}

        elif your_input['option'] == 'encrypt':
            if "message" not in your_input:
                return {"error": "You must provide a message"}
                self.exit = True

            message = int(your_input["message"])
            if message < 0 or message >= p:
                return {"error": f"message must be between 0 and {p - 1}"}
                self.exit = True

            A, b = encrypt(message)
            return {"A": str(list(A)), "b": str(int(b))}

        return {'error': 'Unknown action'}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13412)


### SOLUTION

# The encryption of m is b = A @ S + m * 23 + e, where A and S are uniformly sampled from [-q/2,q/2], and e is a 0-centered normal.
# Therefore, the expected value of A @ S + e is 0. So we can ask the i-th character of the flag encrypted several times,
# calculate the average of all the responses, and that should give roughly 23*FLAG[i] by the Law of Large Numbers.
# The challenge is called Missing Modulus because, if the protocol returned (A@S + m*delta + e) % p, this technique wouldn't be possible.

import socket
import json
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13412 


r = remote(HOST, PORT)

def json_recv(socket):
    line = socket.recv(100000)
    return json.loads(line.decode())

def json_send(socket, message):
    request = json.dumps(message).encode()
    socket.send(request)


flag = ''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(10000), "\n")

    # I made an early request with index = 10000 and the response was that the flag has length 46.
    l = 46
    sample_size = 100
    for i in range(len(flag), l):
        total = 0
        for _ in range(sample_size):
            message = {
                'option': 'get_flag',
                'index': i
            }
            json_send(socket, message)
            response = json_recv(socket)
            # print(response)
            total += int(response['b'])

        print(total//(sample_size*delta))
        flag += chr(total//(sample_size*delta))
        print(flag)


    # response = socket.recv(10000)
    # q = int(response.split(b'"')[1], 16)
    # n = q**2 
    # phi_n = q*(q-1)
    # g = pow(2,q-1,n)
    #
    # params = {
    #     'g': hex(g),
    #     'n': hex(n)
    # }
    # socket.send(json.dumps(params).encode('utf-8'))
    #
    # print(socket.recv(10000), "\n")
    #
    # answer = {
    #     'x': hex(secret)
    # }
    # socket.send(json.dumps(answer).encode('utf-8'))
    #
    # print(socket.recv(10000), "\n")

