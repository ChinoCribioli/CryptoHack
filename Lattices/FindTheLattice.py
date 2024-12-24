# SOURCE

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import math

FLAG = b'crypto{?????????????????????}'


def gen_key():
    q = getPrime(512)
    upper_bound = int(math.sqrt(q // 2))
    lower_bound = int(math.sqrt(q // 4))
    f = random.randint(2, upper_bound)
    while True:
        g = random.randint(lower_bound, upper_bound)
        if math.gcd(f, g) == 1:
            break
    h = (inverse(f, q)*g) % q
    return (q, h), (f, g)
# h = f^{-1}*g mod q, or equivalently, h*f = g mod q

def encrypt(q, h, m):
    assert m < int(math.sqrt(q // 2))
    r = random.randint(2, int(math.sqrt(q // 2)))
    e = (r*h + m) % q
    return e


def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m


public, private = gen_key()
q, h = public
f, g = private

m = bytes_to_long(FLAG)
e = encrypt(q, h, m)

# print(f'Public key: {(q,h)}')
# print(f'Encrypted Flag: {e}')

# OUTPUT

q,h = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
e = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

# SOLUTION

import numpy as np
from GaussianReduction import GaussianReduction

assert( (h < int(math.sqrt(q//2))) == False)

# We are going to perform a reduction in the lattice given by {(a,b): a*h = b mod q}, for which (f,g) is a solution and a short vector as well.
# Thus, if we give a basis for this L and call GaussianReduction, we expect to get (f,g) as the shortest vector of the new reduced basis.
# This is because both f and g are < sqrt(q/2), which is unlikely for two numbers meeting a*h = b (which seems like a pseudorandom relation).

v1 = np.array([1, h])
v2 = np.array([0, q])

sol = GaussianReduction(v1, v2)
# print(sol)

def try_to_decrypt(m):
    print((m%q).to_bytes(48, 'big'))

f, g = sol[0]

assert(f*h % q == g)
assert(f < int(math.sqrt(q//2)))
assert(g < int(math.sqrt(q//2)))

try_to_decrypt(decrypt(q,h,f,g,e))

# Note: This is a simplified version (with numbers instead of polynomials) of a known encryption scheme called
# NTRU: https://en.m.wikipedia.org/wiki/NTRUEncrypt 

# Note: I've been trying to think why setting v2 as (0,q) works and (q,0) or (q,q) don't.
# The idea of having one of these vectors would be to be able to "apply modulo q" when operating
# with the vectors in the lattice, since we can subtract any multiple of q to one of the coordinates
# of the vectors in the lattice.
# My theory is that having (q,q) difficults the application of modulo q in this context because
# we have to subtract the same multiple of q in both coordinates, and this is unnecessarily restrictive.
# And the problem with (q,0) is that we are applying the modulo q in the first coordinate, which
# is quite trivial since we already have a 1 there. Also, to minimize the dot product <v1,v2> when reducing,
# the coordinate that should be taken modulo would be the one with the biggest number, which is the second.

