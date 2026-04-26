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

import socket
import json
import ast
import numpy as np
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13412 


r = remote(HOST, PORT)

def json_recv(socket):
    line = socket.recv(200000)
    # For some reason, some responses are split into two lines, so I have to do this because only the first line is not a valid JSON.
    try:
        return json.loads(line)
    except:
        line += socket.recv(200000)
        return json.loads(line)

def json_send(socket, message):
    request = json.dumps(message).encode()
    socket.send(request)


As = []
bs = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(20000), "\n")

    # To avoid having more generators than the dimension of the space, we take more than 512 samples. Here, we take 600.
    # Having a number of generators considerably lower than the dimension of the space makes it more likely for us to find the desired vector using LLL.
    for t in range(600):
        if t % 100 == 0:
            print(f"Fetching sample number {t}.")
        message = {
            'option': 'encrypt',
            'message': 0
        }
        json_send(socket, message)
        response = json_recv(socket)
        As.append(ast.literal_eval(response['A']))
        bs.append(int(response['b']))

    matrix = np.array(As, dtype=int).T
    matrix = np.vstack([matrix, np.array(bs, dtype=int)])    
    print(matrix.shape)
    np.savetxt('lattice.txt', matrix, fmt='%d')
    print("lattice saved!")


