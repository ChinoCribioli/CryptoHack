### SOURCE

# from utils import listener
from sage.all import *


FLAG = b"crypto{????????????????????????}"

# dimension
n = 64
# plaintext modulus
p = 257
# ciphertext modulus
q = 1048583

V = VectorSpace(GF(q), n)
S = V.random_element()


def encrypt(m):
    A = V.random_element()
    e = randint(-1, 1)
    b = A * S + m + p * e
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
# listener.start_server(port=13413)

### SOLUTION

import socket
import json
import ast
import numpy as np
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13413 


r = remote(HOST, PORT)

def json_recv(socket):
    line = b''
    # For some reason, some responses are split into more than one line, so I have to do this.
    while True:
        try:
            line += socket.recv(100000)
            return json.loads(line)
        except:
            pass

def json_send(socket, message):
    request = json.dumps(message).encode()
    socket.send(request)


# Generate lattice:

# As = []
# bs = []
#
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
#     socket.connect((HOST, PORT))
#     
#     print(socket.recv(20000), "\n")
#
#     # To avoid having more generators than the dimension of the space, we take more than 512 samples. Here, we take 600.
#     # Having a number of generators considerably lower than the dimension of the space makes it more likely for us to find the desired vector using LLL.
#     dim = 100
#     for t in range(dim):
#         if t % 10 == 0:
#             print(f"Fetching sample number {t}.")
#         message = {
#             'option': 'encrypt',
#             'message': 0
#         }
#         json_send(socket, message)
#         response = json_recv(socket)
#         As.append(ast.literal_eval(response['A']))
#         bs.append(int(response['b']))
#
#     queries_matrix = np.array(As, dtype=int).T
#     modulus_matrix = q * np.identity(dim)
#     lattice = np.vstack([queries_matrix, np.array(bs, dtype=int), modulus_matrix])    
#     print(lattice.shape)
#     np.savetxt('lattice.txt', lattice, fmt='%d')
#     print("lattice saved!")

# Apply LLL reduction

# M = np.loadtxt('lattice.txt', dtype=int)
# print(M.shape)
#
# lat = matrix(M)
# reduction = lat.LLL()
# np.savetxt('e.txt', reduction, fmt='%d')
# print("error array saved!")

# Solve using the error array

# M = np.loadtxt('lattice.txt', dtype=int)
# F_q = GF(q)
# offset = 0
# A = M[:n].T[offset : offset + n]
# A = Matrix(F_q, A.tolist())
# A = Matrix(F_q, As[offset : offset + n])
# b = M[n][offset : offset + n]
# b = vector(F_q, b.tolist())
# b = vector(F_q, bs[offset : offset + n])
# e = np.loadtxt('e.txt', dtype=int)[65][offset : offset + n]
# print(e)
# e = vector(F_q, e.tolist())
#
# for c in e:
#     assert(c <= 1 or c == q-1)
#
# # S = np.linalg.solve(A,b-p*e)
# S = A.solve_right(b-p*e)
# print("S: ", S)
#
# for i in range(30):
#     assert(A[i]*S + p*e[i] == b[i])

S = [30768, 74544, 773049, 291121, 578795, 426496, 22993, 105337, 110054, 272810, 98444, 1029434, 69387, 870446, 158517, 760904, 130424, 512386, 683941, 843602, 563536, 632168, 802632, 109309, 873457, 838922, 816625, 478693, 137044, 899566, 730918, 844761, 100052, 938770, 388600, 984941, 634384, 723221, 237220, 511088, 270266, 777638, 413045, 461100, 105630, 54560, 133220, 881348, 881496, 153010, 236874, 678936, 535516, 1007719, 799375, 638124, 542407, 1022958, 681848, 1012805, 159829, 1005365, 619379, 821861]
F_q = GF(q)
S = vector(F_q, S)

flag = ''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(20000), "\n")

    # I made an early request with index = 10000 and the response was that the flag has length 46.
    l = 46
    for i in range(l):
        message = {
            'option': 'get_flag',
            'index': i
        }
        json_send(socket, message)
        response = json_recv(socket)
        # print(response)
        A = np.array(ast.literal_eval(response['A']), dtype=int)
        A = vector(F_q, A.tolist())
        # b = int(response['b'])
        b = F_q(int(response['b']))

        # print(b - A*S)
        # print(b - A*S + p)
        # print(b - A*S - p)
        char_with_noise = int(b-A*S)
        if char_with_noise > 2*p :
            char_with_noise += p 
            char_with_noise %= q
        else:
            char_with_noise %= p
        flag += chr(char_with_noise)
        print(flag)

