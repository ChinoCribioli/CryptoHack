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

import socket as sckt
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



### The solution to this challenge is very similar to the 'Missing Modulus' challenge:
# We first make a bunch of requests to encrypt the message 0, which give us a lot of samples A_i and b_i = A_i*S + p*e_i. We call d the number of requests.
# After that, we construct a lattice where the first n = 64 rows consist of the matrix containing the A_i's as columns. Thus, the dimension of the elementos of the lattice is d.
# The 65th generator of the lattice is the array of b_i's. But, since we are working in F_q now, we also add the canonical vectors multiplied by q as generators.
# That is, all the vectors of the form (0,0,...,0,q,0,...,0), so that we can apply "modulo q" in the lattice when doing the LLL reduction.
# Now, notice that the vector p*(e_1,e_2,...,e_d) is in the lattice, since p*e_i = b_i - A_i*S.
# Furthermore, since we can "apply modulo q" in the vectors of the lattice, we know that (e_1,e_2,...,e_d) is also in the lattice. That is because
# we can take p*(e_1,...,e_d) and multiply it by p^{-1} mod q, and we get a vector of the form of (1+q*k)*(e_1,...,e_d). Then we can subtract all the 
# q*k terms in each coordinate using the last generators of the lattice, giving us as a result (e_1,...,e_d).
# Now, this last e vector has very low norm, since its coordinates are only -1's, 0's and 1's. Thus, applying LLL to this lattice will give us the values of e_i.
# Using this, we can find S by solving a system of equations in F_q, just as in 'Missing Modulus'.

# Step 1: Generate lattice.

As = []
bs = []

with sckt.socket(sckt.AF_INET, sckt.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(20000), "\n")

    # Here, we set the parameter d explained in the solution as 100. That way we get a dimension bigger than 64.
    dim = 100
    for t in range(dim):
        if t % 10 == 0:
            print(f"Fetching sample number {t}.")
        message = {
            'option': 'encrypt',
            'message': 0
        }
        json_send(socket, message)
        response = json_recv(socket)
        As.append(ast.literal_eval(response['A']))
        bs.append(int(response['b']))

    queries_matrix = np.array(As, dtype=int).T
    modulus_matrix = q * np.identity(dim)
    lattice = np.vstack([queries_matrix, np.array(bs, dtype=int), modulus_matrix])    
    np.savetxt('lattice.txt', lattice, fmt='%d')
    print("lattice saved!")

# Step 2: Apply LLL reduction.

M = np.loadtxt('lattice.txt', dtype=int)
print(M.shape)

lat = matrix(M)
reduction = lat.LLL()
np.savetxt('e.txt', reduction, fmt='%d')
print("error array saved!")

# Step 3: Solve using the error array.

F_q = GF(q)
lat = np.loadtxt('lattice.txt', dtype=int)
offset = 0

As = lat[:n].T[offset : offset + n]
# If I don't give the dimensions of the matrix explicitly, the script fails to find the correct S.
As = Matrix(F_q, As.shape[0], As.shape[1], As.tolist())
bs = lat[n][offset : offset + n]
bs = vector(F_q, bs.tolist())

# We noticed by inspecting the resulting LLL reduction that the 66th vector is the desired (e_1,e_2,...,e_d)
es = np.loadtxt('e.txt', dtype=int)[65][offset : offset + n]
es = vector(F_q, es.tolist())
for e in es:
    assert(e <= 1 or e == q-1)

S = As.solve_right(bs-p*es)
print("S: ", S)

# We check for some values that the secret S indeed works.
for i in range(20):
    assert(As[i]*S + p*es[i] == bs[i])

flag = ''

with sckt.socket(sckt.AF_INET, sckt.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(20000), "\n")

    # I made an early request with index = 10000 and the response was that the flag has length 32.
    l = 32
    for i in range(l):
        message = {
            'option': 'get_flag',
            'index': i
        }
        json_send(socket, message)
        response = json_recv(socket)
        A = np.array(ast.literal_eval(response['A']), dtype=int)
        A = vector(F_q, A.tolist())
        b = F_q(int(response['b']))

        char_with_noise = int(b-A*S)
        # This is the case where the noise e is -1. In this case, b-A*S = m-p, which is negative and therefore it is a number close to q when converted from F_q to integers.
        if char_with_noise > 2*p :
            char_with_noise += p 
            char_with_noise %= q
        else:
            char_with_noise %= p
        flag += chr(char_with_noise)
        print(flag)

