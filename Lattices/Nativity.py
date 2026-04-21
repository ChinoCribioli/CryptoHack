### SOURCE

import numpy as np
from random import SystemRandom
from Crypto.Util.number import bytes_to_long, long_to_bytes

# dimension
n = 64
# number of samples in public key
m = 512
dtype = np.uint16

random = SystemRandom()
sigma = 2.3
def normal(): return round(random.gauss(0, sigma))
def binary(): return random.randrange(2)


FLAG = b"crypto{?????????????????????????????????????????}"


def uniform(shape):
    buffer = [random.randrange(0, 1 << 16) for i in range(np.prod(shape))]
    return np.array(buffer, dtype=dtype).reshape(shape)


def sample(shape, dist):
    return np.fromfunction(np.vectorize(lambda *_: dist()), shape).astype(dtype)


def keygen():
    A = uniform((n, m))
    s = uniform((n,))
    # Here, pk ends up being a (n+1) x m matrix, since s*A gives us a vector of length m. 
    pk = np.vstack((A, s @ A + 2*sample((m,), normal)))
    # And sk is a vector of length m+1.
    sk = np.append(-s, 1).astype(dtype)
    return pk, sk


def encrypt(pk, msg):
    c = pk @ sample((m,), binary) + np.append(np.zeros(n), msg)
    # This encryption ends up being a vector of length n+1, and encodes a bit (either a 1 or a 0).
    return c.astype(dtype)


def decrypt(sk, c):
    return sk.dot(c) & 1


pk, sk = keygen()

msg = np.fromiter([int(i) for i in "{:0{}b}".format(
    bytes_to_long(FLAG), 8 * len(FLAG))], dtype)
ciphertexts = np.vstack([encrypt(pk, b) for b in msg])

# np.savetxt("ciphertexts.txt", ciphertexts, fmt="%d")
# np.savetxt("public_key.txt", pk, fmt="%d")


### SOLUTION

# The decryption process only looks the last bit of <sk,c>. Therefore, we can view all the variables in mod 2 and the decryption will be the same.
# We are going to recover s mod 2, which is enough to decrypt messages because of the previous line.
# If we only look the variables mod 2, the last row of the pk is s*A. If we see it as a column vector, it is A.T*s, where A.T is the transpose of A.
# Since A's dimensions are (64,512), A.T's dimensions are (512,64), and s is a dimension 64 vector. Since we have A (and therefore A.T),
# and we have A.T*s, we can find s as the solution of a system of equations with 64 variables and 512 equations, which is more than enough.

pk = np.loadtxt("public_key.txt", dtype=dtype)

# From now on, we see everything as mod 2.
import galois
GF = galois.GF(2)

# To solve the system of equations, we can take a subset of 64 rows of A.T that make a vectorial subspace of dimension 64.
# That is, 64 linearly independent rows.
# For that, we consider the rows from 'offset' to 'offset + 64' for some convenient value of offset. I tried some values and 52 works.
offset = 52 
A = pk[:-1].T[offset : offset+64]
A = GF(A % 2)
# b = A.T*s. We only consider the corresponding coordinates.
b = pk[-1][offset : offset+64]
b = GF(b % 2)

# Find s as the solution of the system.
s = GF(np.linalg.solve(A, b))

# Check that s is indeed the secret we are looking for.
s = np.array(s)
A = pk[:-1]
b = pk[-1]
assert((s @ A) % 2 == b % 2).all()

# Now, decrypt all the bits given the sk.
sk = np.append(-s, 1)
cts = np.loadtxt("ciphertexts.txt", dtype=dtype)
flag_bits = '0b'
for row in cts:
    flag_bits += str(decrypt(sk,row))

flag = long_to_bytes(int(flag_bits,2))
print(flag)
