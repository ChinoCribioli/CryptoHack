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
        # print(line)
        return json.loads(line)
    # return json.loads(line.decode())

def json_send(socket, message):
    request = json.dumps(message).encode()
    socket.send(request)


flag = ''
As = []
bs = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(20000), "\n")

    # I made an early request with index = 10000 and the response was that the flag has length 46.
    l = 46
    for _ in range(600):
        message = {
            'option': 'get_flag',
            'index': 0
        }
        json_send(socket, message)
        response = json_recv(socket)
        # print(response)
        As.append(ast.literal_eval(response['A']))
        bs.append(int(response['b']))

    matrix = np.array(As, dtype=int).T
    matrix = np.vstack([matrix, np.array(bs, dtype=int)])    
    print(matrix.shape)
    np.savetxt('MissingModulus.txt', matrix, fmt='%d')
    print("matrix saved!")



# lat = matrix(A).augment(vector(b))
# lat = lat.augment(q * identity_matrix(625)) # I add the canonical base times q to represent "taking modulo q" in each coordinate in the lattice
# lat = lat.transpose()
# sol = lat.LLL()







# The encryption of m is b = A @ S + m * 23 + e, where A and S are uniformly sampled from [-q/2,q/2], and e is a 0-centered normal.
# Therefore, the expected value of A @ S + e is 0. So we can ask the i-th character of the flag encrypted several times,
# calculate the average of all the responses, and that should give roughly 23*FLAG[i] by the Law of Large Numbers.
# The challenge is called Missing Modulus because, if the protocol returned (A@S + m*delta + e) % p, this technique wouldn't be possible.

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(20000), "\n")

    # I made an early request with index = 10000 and the response was that the flag has length 46.
    l = 46
    sample_size = 10000
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
