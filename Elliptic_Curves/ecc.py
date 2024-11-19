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

# alice_secret = PohligHellman(G, public, factors, curve.add, ec_mult, curve.O())
alice_secret = 203194937053061868556704865251970439522
shared_secret = curve.multiply(alice_secret, B).x
assert(decrypt_flag(shared_secret, output['iv'], output['encrypted_flag']) == 'crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}')

###################################################################


#	SOURCE CODE:

#!/usr/bin/env python3

import fastecdsa
from fastecdsa.point import Point
# from utils import listener


FLAG = "crypto{????????????????????????????????????}"
G = fastecdsa.curve.P256.G
assert G.x, G.y == [0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5]


class Challenge():
    def __init__(self):
        self.before_input = "Welcome to my secure search engine backed by trusted certificate library!\n"
        self.trusted_certs = {
            'www.cryptohack.org': {
                "public_key": Point(0xE9E4EBA2737E19663E993CF62DFBA4AF71C703ACA0A01CB003845178A51B859D, 0x179DF068FC5C380641DB2661121E568BB24BF13DE8A8968EF3D98CCF84DAF4A9),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.bing.com': {
                "public_key": Point(0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.gchq.gov.uk': {
                "public_key": Point(0xDEDFC883FEEA09DE903ECCB03C756B382B2302FFA296B03E23EEDF94B9F5AF94, 0x15CEBDD07F7584DBC7B3F4DEBBA0C13ECD2D2D8B750CBF97438AF7357CEA953D),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            }
        }

    def search_trusted(self, Q):
        for host, cert in self.trusted_certs.items():
            if Q == cert['public_key']:
                return True, host
        return False, None

    def sign_point(self, g, d):
        return g * d

    def connection_host(self, packet):
        d = packet['private_key']
        if abs(d) == 1:
            return "Private key is insecure, certificate rejected."
        packet_host = packet['host']
        curve = packet['curve']
        g = Point(*packet['generator'])
        Q = self.sign_point(g, d)
        cached, host = self.search_trusted(Q)
        if cached:
            return host
        else:
            self.trusted_certs[packet_host] = {
                "public_key": Q,
                "curve": "secp256r1",
                "generator": G
            }
            return "Site added to trusted connections"

    def bing_it(self, s):
        return f"Hey bing! Tell me about {s}"

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        host = self.connection_host(your_input)
        if host == "www.bing.com":
            return self.bing_it(FLAG)
        else:
            return self.bing_it(host)


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13382)

#	SOLUTION

import socket
import json
HOST = "socket.cryptohack.org"
PORT = 13382

order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 # order of the curve secp256r1
# Note that, in my packet in method connection_host, I send a private key candidate but I also send my own point generator.
# Thus, the challenge is not to find an x such that g^x = pk, but to find an x AND a base point b such that b^x = pk.
# Taking b = pk^((order+1)/2) and x = 2 works since b^(order+1) = b for any b.
target_pk = Point(0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A)
bait = target_pk * ((order+1)//2)

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.connect((HOST, PORT))
    # print(s.recv(10000))
    # challenge = {
    # 	'private_key': 2,
    # 	'host': 'www.bing.com',
    # 	'curve': "secp256r1",
    # 	'generator': [bait.x, bait.y]
    # }

    # s.send(json.dumps(challenge).encode('utf-8'))
    # print(s.recv(10000))


#######################################################################################

#	SOURCE CODE:

#!/usr/bin/env python3

import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa.ecdsa import Public_key, Private_key, Signature, generator_192
# from utils import listener
from datetime import datetime
from random import randrange

FLAG = "crypto{?????????????????????????}"
g = generator_192
n = g.order()

class Challenge():
    def __init__(self):
        self.before_input = "Welcome to ProSign 3. You can sign_time or verify.\n"
        secret = randrange(1, n)
        self.pubkey = Public_key(g, g * secret)
        self.privkey = Private_key(self.pubkey, secret)

    def sha1(self, data):
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        return sha1_hash.digest()

    def sign_time(self):
        now = datetime.now()
        m, n = int(now.strftime("%m")), int(now.strftime("%S"))
        current = f"{m}:{n}"
        msg = f"Current time is {current}"
        hsh = self.sha1(msg.encode())
        sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))
        return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}

    def verify(self, msg, sig_r, sig_s):
        hsh = bytes_to_long(self.sha1(msg.encode()))
        sig_r = int(sig_r, 16)
        sig_s = int(sig_s, 16)
        sig = Signature(sig_r, sig_s)

        if self.pubkey.verifies(hsh, sig):
            return True
        else:
            return False

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'sign_time':
            signature = self.sign_time()
            return signature

        elif your_input['option'] == 'verify':
            msg = your_input['msg']
            r = your_input['r']
            s = your_input['s']
            verified = self.verify(msg, r, s)
            if verified:
                if msg == "unlock":
                    self.exit = True
                    return {"flag": FLAG}
                return {"result": "Message verified"}
            else:
                return {"result": "Bad signature"}

        else:
            return {"error": "Decoding fail"}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13381)

#	SOLUTION

HOST = "socket.cryptohack.org"
PORT = 13381

# If we notice in the implementation that the random number k is chosen in the range [1,n], and that n < 60
# (because it is the number in the seconds marker in the current time 'now'), we can brute force the secret value k given that
# we are given with r, which is the x coordinate of kG.

x_coordinates = {}
for i in range(1,60):
	x_coordinates[(i*generator_192).x()] = i
	# Now, given r, we know that the respective k is x_coordinates[r]

# Now, a given a valid signature, we know that s = k^{-1}(H(m)+dr) must hold. Therefore, given a signature and having k,
# we can extract the secret d by doing sk - H(m) = dr ---> (sk - H(m))/r = d

# SPANISH GIBBERISH (an approach I had before. It is incorrect but I don't want to erase it and I'm too lazy to translate it):
# s = k^{-1}(H(m)+dr)   -----> s^{-1} = k(H(m)+dr)^{-1}
# Me dan una firma (r,s) tal que H(m)s^{-1} + drs^{-1} = k, con m = "La hora es x".
# O sea que cumple que  H(m)s{-1}*P+rs{-1}*Q = kP, que es igual a
# H(m)*P + r*Q = s(kP)
# Observacion: Dado r no puedo recuperar k pero si kP (pues saber la coordenada x te da o bien kP o -kP, y podes probar los dos).
# Ahora, quiero s' tal que H(m')*P + r*Q = s'(kP) donde m' = "unlock".
# Si resto, tengo (H(m)-H(m'))*P = (s-s')(kP). Tengo s, (H(m)-H(m')) y kP
# H(m)*P - s*kP = H(m')*P - s'*(kP)
# Si hago q = H(m')/H(m) y mando (q*r,q*s), eso anda? No porque estas modificando el r pero no el k, que estan  relacionados.


# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
#     ch = Challenge()
#     target_hash = ch.sha1("unlock".encode())

#     socket.connect((HOST, PORT))
    
#     print(socket.recv(10000), "\n")
#     challenge = {
#     	'option': 'sign_time',
#     }
#     socket.send(json.dumps(challenge).encode('utf-8'))
#     response = json.loads(socket.recv(10000))
#     print(response)
#     # socket.send(json.dumps(challenge).encode('utf-8'))
#     # signature = json.loads(socket.recv(10000))
#     m1 = response['msg']
#     h1 = ch.sha1(m1.encode())
#     r = int(response['r'], 16)
#     s = int(response['s'], 16)
#     k = x_coordinates[r]
#     h1_int = bytes_to_long(h1)
#     d = (s*k - h1_int) * pow(r, -1, g.order())
#     d %= g.order()

#     m2 = "unlock"
#     h2 = ch.sha1(m2.encode())
#     h2_int = bytes_to_long(h2)

#     # s = k^{-1}(H(m)+dr)
#     new_s = (h2_int + d*r) * pow(k, -1, g.order())
#     new_s %= g.order()
#     challenge = {
#     	'option': 'verify',
#     	'msg': "unlock",
#     	'r': hex(r),
#     	's': hex(new_s)
#     }
#     socket.send(json.dumps(challenge).encode('utf-8'))
#     print(socket.recv(10000), "\n")


##################################################################################################################


#	SOURCE CODE:

import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = b"crypto{??????????????????????????????????????}"

def gen_keypair(G, p):
    n = random.randint(1, (p-1))
    P = n*G
    return n, P

def gen_shared_secret(P, n):
    S = P*n
    return S.x()

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

# Define Curve params
p = 1331169830894825846283645180581
a = -35
b = 98
# E = EllipticCurve(GF(p), [a,b])
# G = E.gens()[0]

from ecdsa.ellipticcurve import CurveFp, PointJacobi
curve = CurveFp(p, a, b)
G = PointJacobi(curve, 479691812266187139164535778017, 568535594075310466177352868412, 1)

# Generate keypair
n_a, P1 = gen_keypair(G, p)
n_b, P2 = gen_keypair(G, p)

# Calculate shared secret
S1 = gen_shared_secret(P1, n_b)
S2 = gen_shared_secret(P2, n_a)

# Check protocol works
assert S1 == S2

flag = encrypt_flag(S1)

# print(f"Generator: {G}")
# print(f"Alice Public key: {P1}")
# print(f"Bob Public key: {P2}")
# print(f"Encrypted flag: {flag}")

#	DATA

# Generator: (479691812266187139164535778017 : 568535594075310466177352868412 : 1)
# Alice Public key: (1110072782478160369250829345256 : 800079550745409318906383650948 : 1)
# Bob Public key: (1290982289093010194550717223760 : 762857612860564354370535420319 : 1)
# Encrypted flag: {'iv': 'eac58c26203c04f68d63dc2c58d79aca', 'encrypted_flag': 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'}

#	SOLUTION

# I created a script in sage (movAttack.sage) that performs a mov attack on the point A, which gave that Alice's private key is
a = 29618469991922269 
B_pub = PointJacobi(curve, 1290982289093010194550717223760, 762857612860564354370535420319, 1)

shared_secret = gen_shared_secret(B_pub, a)
data = {'iv': 'eac58c26203c04f68d63dc2c58d79aca', 'encrypted_flag': 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'}

def decrypt_flag(data, shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    iv = bytes.fromhex(data['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = cipher.decrypt(bytes.fromhex(data['encrypted_flag']))
    return flag

    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data

print(decrypt_flag(data, shared_secret))


# DATAZO: Si p es 1153763334005213, el factor mas grande de la factorizacion del orden de G, cumple que
# p-1 = 2^2 * 7 * 271^2 * 23687^2, que son todos tambien factores del orden de G