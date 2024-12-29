# SOURCE

# from utils import listener
from sage.all import *


FLAG = b"crypto{????????????????????????}"

# dimension
n = 64
# plaintext modulus
p = 257
# ciphertext modulus
q = 0x10001

V = VectorSpace(GF(q), n)
S = V.random_element()

def encrypt(m):
    A = V.random_element()
    b = A * S + m
    return A, b


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
# listener.start_server(port=13411)

# SOLUTION

from pwn import * # pip install pwntools
import json

r = remote('socket.cryptohack.org', 13411)#, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(message):
    request = json.dumps(message).encode()
    r.sendline(request)


# First, we can encrypt any number we want. So we are going to get a lot of encryptions of 0.
# This is going to get us a lot of tuples of the form (A, <A,S>).
# With enough of these entries, I can solve a linear system of equations to get S.
# The number of entries I need is the dimension of the vector space, which is n = 64.

print(r.recvline())

coefficients = []
values = []

# for i in range(64):
for i in range(0):
    if i % 10 == 0:
        print(f"Step {i+1}")
    query = {
        'option': 'encrypt',
        'message': 0
    }
    json_send(query)
    response = json_recv()
    values.append(int(response['b']))
    coefficients.append([int(a) for a in response['A'][1:-1].split(',')])

import numpy as np
# from galois import GF
#
# F = GF(q)
#
# coefficients = F(coefficients)
# values = F(values)
# S = np.linalg.solve(coefficients, values).ravel().tolist()
# print(S)
S = np.array([22332, 45849, 52420, 9047, 60252, 2297, 47072, 37386, 48270, 49481, 48302, 38130, 18692, 55229, 33832, 40579, 19749, 34008, 64545, 4043, 44202, 30733, 24901, 24913, 64573, 56142, 6834, 30629, 7132, 26775, 44826, 25721, 6919, 14772, 6918, 30690, 7077, 8997, 63039, 1398, 60005, 49985, 56067, 64685, 10739, 42738, 27585, 52177, 33192, 48946, 61179, 34136, 60121, 12673, 64578, 30864, 31947, 60456, 64444, 61913, 664, 41636, 43293, 26559])
assert(len(S) == 64)

# Now that we got S, we just get every char of the flag encrypted and decrypt them.
flag = ''
for i in range(1000):
    query = {
        'option': 'get_flag',
        'index': i
    }
    json_send(query)
    response = json_recv()
    b = int(response['b'])
    A = np.array([int(a) for a in response['A'][1:-1].split(',')])
    b -= A.dot(S)
    flag += chr(b%q)
    print(flag)
