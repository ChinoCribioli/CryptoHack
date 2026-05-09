### 	SOURCE
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os

from Starter import WeierstrassEllipticCurve, ECPoint, decrypt_flag

def gen_shared_secret(curve, Q: tuple, n: int):
    # Bob's Public key, my secret int
    S = curve.multiply(n, Q)
    return S.x


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data

# Define the curve
p = 310717010502520989590157367261876774703
a = 2
b = 3
curve = WeierstrassEllipticCurve(a,b,p)

# Generator
g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = ECPoint(curve, g_x, g_y)

# # My secret int, different every time!!
# n = randint(1, p)

# # Send this to Bob!
# public = curve.multiply(n, G)
# print("public:", public.export())

# Bob's public key
b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = ECPoint(curve, b_x, b_y)

# # Calculate Shared Secret
# shared_secret = gen_shared_secret(curve, B, n)

# # Send this to Bob!
# ciphertext = encrypt_flag(shared_secret)
# print(ciphertext)

# 	DATA:

output = {'iv': '07e2628b590095a5e332d397b8a59aa7', 'encrypted_flag': '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'}
public = ECPoint(curve, 280810182131414898730378982766101210916, 291506490768054478159835604632710368904)

# 	SOLUTION:

# I used sage to calculate the order of the elliptic curve, which gave me:
order = 310717010502520989590206149059164677804
# Now, I can use Pohlig–Hellman.
# I factored this order and gave me these factors (each (p,e) pair is such that p^e is a power in 'order' prime factorization):
factors = [(2,2), (3,7), (139,1), (165229,1), (31850531,1), (270778799,1), (179317983307,1)]
factors_check = 1
for p,e in factors:
	factors_check *= (p**e)
assert(factors_check == order)
assert(curve.multiply(order,G).export() == (None,None))

def MultipleChineseRemainderTheorem(remainders): # A list of restrictions in the form of (remainder_i, modulo_i)
	if len(remainders) == 1:
		return remainders[0]
	(r1,m1) = remainders[-1]
	(r2,m2) = remainders[-2]
	remainders = remainders[:-2]
	newmod = m1*m2
	remainders.append(( (r1*m2*pow(m2,-1,m1) + r2*m1*pow(m1,-1,m2)) % newmod , newmod))
	return MultipleChineseRemainderTheorem(remainders)

assert(MultipleChineseRemainderTheorem([(2,3), (3,4), (1,5)]) == (11,60))
assert(MultipleChineseRemainderTheorem([(2,3), (0,4)]) == (8,12))

def BabyStepGiantStep(g, A, n, multiply, exponentiate, identity, order = 0):
	# Calculates x such that g^x == A.
	# We pass the operations and the identity of the group as parameters to fit the implmentation to any group
	if not order:
		order = n
	m = int(order**.5)+1
	babysteps = {}
	iterator = identity
	for j in range(m+1):
		babysteps[iterator.export()] = j
		iterator = multiply(g,iterator)
	giantstep = exponentiate(g,-m)
	iterator = A
	step_keys = babysteps.keys()
	for i in range(m):
		if iterator.export() in step_keys:
			return i*m+babysteps[iterator.export()]
		iterator = multiply(giantstep,iterator)
	return None

# Test our implementation of BSGS for generic groups (an Elliptic Curve in this case):
n_test = randint(1,100000)
G_test = curve.multiply((order//165229),G)
P_test = curve.multiply(n_test,G_test)
ec_mult = lambda a,b: curve.multiply(b,a) # The inputs are switched for the sake of compatibility
# assert(BabyStepGiantStep(G_test, P_test, 165229, curve.add, ec_mult, curve.O()) == n_test)

def PohligHellman(g, A, factors, mult, exp, identity):
    n = 1
    for p,e in factors:
    	n *= p**e
    remainders = []
    for (p,e) in factors:
    	p_i = p**e
    	cofactor = n//p_i
    	g_i = exp(g,cofactor)
    	A_i = exp(A,cofactor)
    	x_k = 0
    	gamma = exp(g_i,p_i//p)
    	for k in range(e):
    		h_k = exp(mult(exp(g_i,-x_k), A_i),p**(e-1-k))
    		d_k = BabyStepGiantStep(gamma, h_k, p, mult, exp, identity)
    		x_k += d_k*p**k
    	remainders.append((x_k,p_i))
    a = MultipleChineseRemainderTheorem(remainders)[0]
    return a

alice_secret = PohligHellman(G, public, factors, curve.add, ec_mult, curve.O())
assert(alice_secret == 203194937053061868556704865251970439522)
shared_secret = curve.multiply(alice_secret, B).x
print(decrypt_flag(shared_secret, output['iv'], output['encrypted_flag']))
