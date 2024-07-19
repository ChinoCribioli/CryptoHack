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
		R0, R1 = (P, self.add(P,P))
		bits = []
		while k > 0:
			bits.append(k&1)
			k //= 2
		bits = bits[::-1]
		for bit in bits:
			if bit:
				R0, R1 = (self.add(R0,R1),self.add(R1,R1))
			else:
				R0, R1 = (self.add(R0,R0),self.add(R0,R1))
		return R0


curve = MontgomeryEllipticCurve(486662, 1, (1<<255)-19)
G = curve.from_x_coordinate(9)
Q = curve.Montgomerys_binary_algorithm(0x1337c0decafe,G)
print(Q.x)