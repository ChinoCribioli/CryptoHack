from TonelliShanks import TS
from Starter import ECPoint

class MontgomeryEllipticCurve():
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
