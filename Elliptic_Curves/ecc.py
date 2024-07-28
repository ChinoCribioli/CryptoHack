from TonelliShanks import TS

class WeierstrassEllipticCurve():
	def __init__(self, a, b, p):
		assert( (4*a**3+27*b**2) % p != 0)
		self.a = a
		self.b = b
		self.p = p

	def O(self):
		return ECPoint(self, None, None)

	def assert_in_curve(self, P):
		(x, y) = P.export()
		assert(y**2 % self.p == (x**3+self.a*x+self.b) % self.p)

	def add(self, P, Q):
		if P.isZero:
			return Q
		if Q.isZero:
			return P
		(x1,y1) = P.export()
		(x2,y2) = Q.export()
		if x1 == x2 and y1 == -y2 % self.p :
			return ECPoint(self,None,None)
		if P == Q:
			lamb = (3*x1**2+self.a)*pow(2*y1,-1,self.p)
		else:
			lamb = (y2-y1)*pow(x2-x1,-1,self.p)
		lamb %= self.p
		x3 = lamb**2-x1-x2
		y3 = lamb*(x1-x3)-y1
		return ECPoint(self, x3, y3)
		# Explanation: lambda is the slope of the line drawn to compute the sum. It is the usual (y2-y1)/(x2-x1) when x1 != x2 and
		# (3x1^2+a)/(2y1) if x1 == x2 since it is the tangent to the curve in that point (we know P == Q since the case P == -Q was dealt earlier).
		# This last formula is because the gradient of the curve is (3x^2+a,2y), and the slope we are looking for
		# is the slope of that gradient. Another way to think about this is that if we have a curve given implicitly by
		# f(y) = g(x), then the explicit form will be (at least locally) y = f^{-1}(g(x)), and the derivative
		# of that will be f^{-1}'(g(x))*g'(x) = g'(x)/f'(f^{-1}(g(x))) = g'(x)/f'(y) since f^{-1}(g(x)) = y.
		# Now with the slope, we know that our third point (x3,y3) will satisfy the curve equation and the line equation which is
		# y = lambda(x-x1)+y1. If we plug this into the curve equation, we get x^3+ax+b = lambda^2(x^2-2x*x1+x1^2)+y1^2+lambda*y1(x-x1).
		# Now, we know that the 3 roots of this are x1,x2,x3, and the coefficient of x^2 in this polynomial is -lambda^2. Therefore
		# -lambda^2 = -x1-x2-x3 => lambda^2-x1-x2 = x3. And we get -y3 simply by plugging x3 in the y = lambda(x-x1)+y1 equation.


	def multiply(self, n, P):
		if n < 0:
			P = P.negative()
			n *= -1
		R = self.O()
		Q = P
		while n > 0:
			if n%2:
				R = self.add(R,Q)
			Q = self.add(Q,Q)
			n //= 2
		return R

	def from_x_coordinate(self, x):
		y2 = (x**3+self.a*x+self.b)%self.p # This is y^2
		y = TS(y2,self.p)
		return ECPoint(curve, x, y)

curve = WeierstrassEllipticCurve(497, 1768, 9739)

class ECPoint():
	def __init__(self, ec, x, y):
		self.ec = ec
		if x == None :
			self.isZero = True
			self.x = None
			self.y = None
			return
		self.isZero = False
		self.x = x % self.ec.p
		self.y = y % self.ec.p

	def export(self):
		return (self.x, self.y)

	def negative(self):
		if self.isZero:
			return self
		return ECPoint(self.ec, self.x, (-self.y)%self.ec.p)

	def assert_in_curve(self):
		self.ec.assert_in_curve(self)


P = ECPoint(curve, 8045, 6936)
O = curve.O()
assert(P.negative().export() == (8045, 2803))
assert(O.negative().export() == (None, None))

X = ECPoint(curve,5274,2841)
Y = ECPoint(curve,8669,740)
assert(curve.add(X,Y).export() == (1024,4440))
assert(curve.add(Y,X).export() == (1024,4440))
assert(curve.add(X,X).export() == (7284,2107))
assert(curve.add(X,X.negative()).export() == (None,None))
assert(curve.add(X,O) == X)
assert(curve.add(O,X) == X)

P = ECPoint(curve, 493, 5564)
Q = ECPoint(curve, 1539, 4742)
R = ECPoint(curve, 4403, 5202)
S = curve.add(curve.add(P,P),curve.add(Q,R))
S.assert_in_curve()
assert(S.export() == (4215, 2162))

X = ECPoint(curve,5323,5438)
assert(curve.multiply(1337,X).export() == (1089,6931))
P = ECPoint(curve,2339,2213)
Q = curve.multiply(7863,P)
Q.assert_in_curve()
assert(Q.export() == (9467, 2742))

############################################################

G = ECPoint(curve,1804,5368)
Q_A = ECPoint(curve,815,3190)
n_B = 1829
secret_point = curve.multiply(n_B, Q_A)
secret = str(secret_point.export()[0])
from hashlib import sha1
secret = sha1(secret.encode())
assert(secret.hexdigest() == '80e5212754a824d3a4aed185ace4f9cac0f908bf')

############################################################

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


n_B = 6534
x_Q_A = 4726

secret_point = curve.from_x_coordinate(x_Q_A)
secret_point.assert_in_curve()
secret_point = curve.multiply(n_B, secret_point)
secret_point.assert_in_curve()

shared_secret = secret_point.export()[0]
iv = 'cd9da9f1c60925922377ea952afc212c'
ciphertext = 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'

assert(decrypt_flag(shared_secret, iv, ciphertext) == 'crypto{3ff1c1ent_k3y_3xch4ng3}')

##############################################################################

class MontgomeryEllipticCurve():
	# TODO: make both EC classes inherit a father class since the methods init, O, and multiply are the same. The assert in the init of WEC can be added by overriding the constructor of the father class
	def __init__(self, a, b, p):
		self.a = a
		self.b = b
		self.p = p

	def O(self):
		return ECPoint(self, None, None)

	def assert_in_curve(self, P):
		(x, y) = P.export()
		assert((self.b*y**2) % self.p == (x**3+self.b*x**2+x) % self.p)

	def add(self, P, Q):
		if P.isZero:
			return Q
		if Q.isZero:
			return P
		(x1,y1) = P.export()
		(x2,y2) = Q.export()
		if x1 == x2 and y1 == -y2 % self.p :
			return ECPoint(self,None,None)
		if P == Q:
			alpha = (3*x1**2+2*self.a*x1+1)*pow(2*y1*self.b,-1,self.p)
		else:
			alpha = (y2-y1)*pow(x2-x1,-1,self.p)
		alpha %= self.p
		x3 = self.b*alpha**2-self.a-x1-x2
		y3 = alpha*(x1-x3)-y1
		return ECPoint(self, x3, y3)

	def multiply(self, n, P):
		if n < 0:
			P = P.negative()
			n *= -1
		R = self.O()
		Q = P
		while n > 0:
			if n%2:
				R = self.add(R,Q)
			Q = self.add(Q,Q)
			n //= 2
		return R

	def from_x_coordinate(self, x):
		y2 = (x**3+self.a*x**2+x)*pow(self.b,-1,self.p)%self.p # This is y^2
		y = TS(y2,self.p)
		return ECPoint(curve, x, y)

	def Montgomerys_binary_algorithm(self, k, P):
		if k < 0:
			P = P.negative()
			k *= -1
		R0, R1 = (P, self.add(P,P))
		bits = []
		while k > 0:
			bits.append(k&1)
			k //= 2
		bits = bits[::-1]
		bits = bits[1:]
		for bit in bits:
			if bit:
				(R0, R1) = (self.add(R0,R1),self.add(R1,R1))
			else:
				(R0, R1) = (self.add(R0,R0),self.add(R0,R1))
		return R0


curve = MontgomeryEllipticCurve(486662, 1, (1<<255)-19)
G = curve.from_x_coordinate(9)
Q = curve.Montgomerys_binary_algorithm(0x1337c0decafe,G)
assert(Q.x == 49231350462786016064336756977412654793383964726771892982507420921563002378152)

# Here's an explanation on why this binary algorithm works, as well as a code that illustrates this by doing it to
# plain numbers instead of EC points.

def binary_algorithm_explanation(k):
	# At each step, R0 will be the prefix of k written in binary and R1 will be R0+1.
	# In other words: at iteration i of the loop, R0's binary representation will be the first i+1 bits of k.
	# If the upcoming bit is a 0, we just have to double R0 (and add R0 to R1 to maintain the invariant).
	# If it is a 1, we have to double R0 and add 1, or add R1, which is the same as R0+1 (and double R1 to maintain the invariant).
	R0, R1 = (1, 2)
	bits = []
	while k > 0:
		bits.append(k&1)
		k //= 2
	bits = bits[::-1]
	bits = bits[1:]
	for bit in bits:
		if bit:
			(R0, R1) = (R0+R1,2*R1)
		else:
			(R0, R1) = (2*R0,R0+R1)
		print(f"R0: {R0}, R1: {R1}")
	return R0

# binary_algorithm_explanation(11)

###################################################################

# 	SOURCE CODE:
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os

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
assert(BabyStepGiantStep(G_test, P_test, 165229, curve.add, ec_mult, curve.O()) == n_test)

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

# alice_secret = PohligHellman(G, public, factors, curve.add, ec_mult, curve.O())
alice_secret = 203194937053061868556704865251970439522
shared_secret = curve.multiply(alice_secret, B).x
assert(decrypt_flag(shared_secret, output['iv'], output['encrypted_flag']) == 'crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}')

###################################################################

