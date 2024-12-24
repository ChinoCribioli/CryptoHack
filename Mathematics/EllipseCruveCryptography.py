# SOURCE CODE:

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *
from hashlib import sha1
import random
import os

from collections import namedtuple
# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

FLAG = b"crypto{????????????????????????????????}"  # REMOVE ME


# The invariant is x^2 - D*y^2 == 1 in F_p
def point_addition(P, Q):
    Rx = (P.x*Q.x + D*P.y*Q.y) % p
    Ry = (P.x*Q.y + P.y*Q.x) % p
    return Point(Rx, Ry)


def scalar_multiplication(P, n):
    Q = Point(1, 0)
    while n > 0:
        if n % 2 == 1:
            Q = point_addition(Q, P)
        P = point_addition(P, P)
        n = n//2
    return Q


def gen_keypair():
    private = random.randint(1, p-1)
    public = scalar_multiplication(G, private)
    return (public, private)


def gen_shared_secret(P, d):
    return scalar_multiplication(P, d).x


def encrypt_flag(shared_secret: int, flag: bytes):
    # Derive AES key from shared secret
    key = sha1(str(shared_secret).encode('ascii')).digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(flag, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data


# ================ #
# Curve parameters #
# ================ #
p = 173754216895752892448109692432341061254596347285717132408796456167143559
D = 529
G = Point(29394812077144852405795385333766317269085018265469771684226884125940148,
          94108086667844986046802106544375316173742538919949485639896613738390948)

A, n_a = gen_keypair()
B, n_b = gen_keypair()
assert (A.x**2 - D*A.y**2) % p == 1
assert (B.x**2 - D*B.y**2) % p == 1

# print(f"Alice's public key: {A}")
# print(f"Bob's public key: {B}")

shared_secret = gen_shared_secret(B, n_a)
flag_enc = encrypt_flag(shared_secret, FLAG)

# print(f'Encrypted flag: {flag_enc}')

# OUTPUT:

# Alice's public key:
A = Point(x=155781055760279718382374741001148850818103179141959728567110540865590463, y=73794785561346677848810778233901832813072697504335306937799336126503714)
# Bob's public key:
B = Point(x=171226959585314864221294077932510094779925634276949970785138593200069419, y=54353971839516652938533335476115503436865545966356461292708042305317630)
#Encrypted flag:
encrypted_flag = {'iv': '64bc75c8b38017e1397c46f85d4e332b', 'encrypted_flag': '13e4d200708b786d8f7c3bd2dc5de0201f0d7879192e6603d7c5d6b963e1df2943e3ff75f7fda9c30a92171bbbc5acbf'}


# SOLUTION:

# We include Tonelli_Shanks to compute square roots.

def gcd(a,b):
	if b > a:
		return gcd(b,a)
	if b == 0:
		return a
	return gcd(b,a%b)

assert(gcd(66528,52920) == 1512)

def AuxEEA(r0,s0,t0,r1,s1,t1):
	if r1 == 0:
		return (r0,s0,t0)
	q = r0//r1
	return AuxEEA(r1,s1,t1,r0-q*r1,s0-q*s1,t0-q*t1)

def extendedEucldeanAlgorithm(a,b):
	if b > a:
		unordered = AuxEEA(b,1,0,a,0,1)
		return (unordered[0], unordered[2], unordered[1])
	return AuxEEA(a,1,0,b,0,1)

from random import randint
import copy

def Tonelli_Shanks(a,p): # Finds r such that r^2 = a (mod p)
	if a%p == 0:
		return 0
	exp = (p-1)//2
	# First, write p-1 = q*2^s
	q = p-1
	s = 0
	while q%2 == 0:
		q //= 2
		s += 1
	# Then, find a quadratic non-residue
	b = randint(2,p)
	while pow(b,exp,p) != p-1:
		b = randint(2,p)
	
	r = pow(a,(q+1)//2,p)
	t = pow(a,q,p)
	# These variables satisfy r^2 = a*t
	bq = pow(b,q,p)
	m = copy.copy(s)
	while t != 1:
		index = 0 # This will be the greatest k such that t^2^k != 1, that we know it will be equal to -1
		for i in range(m,0,-1):
			if pow(t,2**i,p) == p-1:
				index = i
				break
		m = copy.copy(index)
		new_factor = pow(bq,2**(s-2-index),p)
		t *= new_factor**2
		t %= p
		# Now, new_t^2^index = prev_t^2^index * new_factor^2^{index+1} = (-1)*(-1) = 1.
		# But we have to adjust r to keep the equality r^2 = a*t
		r *= new_factor
		r %= p
	return r


# We are going to perform several transformations to the set of points on the ellipse to solve this.
# First, we compute sqrt(D) mod p in order to compute f(x,y) = (x,sqrt(D)*y). This bijection sends the points of the ellipse E to
# the set of points H = {(x,y): x^2 - y^2 = 1}, which can be seen as an ellipse but as a hiperbola as well.
# Notice that if we consider the operation '+' in this new set H as (x1,y1) + (x2,y2) = (x1x2 + y1y2, x1y2 + x2y1),
# we have that f(P+Q) = f(P) + f(Q), where the first + is +_E and the second one is +_H.
# So this transformation gives us a new group such that f(A) = a*f(G), where a is the 
# private key we want to get.

sqrt_D = Tonelli_Shanks(D,p)
assert(pow(sqrt_D, 2, p) == D)

def rescale_D(P):
    return Point(P.x, (sqrt_D * P.y) % p)

fA = rescale_D(A)
fG = rescale_D(G)


# Now, we note that a point in H meets that 1 = x^2 - y^2 = (x+y)(x-y). Therefore, we can compute 
# g(x,y) = (x+y, x-y), which is another bijection that sends H to the set S = {(x,y): xy = 1}.
# Additionally, notice that if we denote * as the coordinate-wise multiplication, we can prove that
# g(P+Q) = g(P) * g(Q), where + is +_H, the addition in H. So now we have another group in which
# g(f(A)) = g(f(G))^a (written in multiplicative notation), and where the operation is the
# multiplication coordinate by coordinate.
# This therefore reduces the problem to a DLP in F_p.

def reduce_to_F_p(P):
    return (P.x + P.y) % p

pub = reduce_to_F_p(fA)
gen = reduce_to_F_p(fG)

# Now we have to solve a DLP in F_p, which is easy because p-1 is smooth. Concretely,
assert( p-1 == 2 * 567307171 * 657631441 * 671619593 * 710437279 * 739003417 * 813892307 * 821078411 * 988228543 )

# But since I'm lazy, I'm just gonna print it and ask sage to do it lol.
print(f"pub = {pub}\ngen = {gen}")
private_key = 85659350935432836744105386596354218808820976897571304400328185351959247

assert(pow(gen, private_key, p) == pub)
assert(scalar_multiplication(G, private_key).x == A.x)

def decrypt_flag(shared_secret: int, data: bytes):
    # Derive AES key from shared secret
    key = sha1(str(shared_secret).encode('ascii')).digest()[:16]
    # Encrypt flag
    iv = bytes.fromhex(data['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    text = cipher.decrypt(bytes.fromhex(data['encrypted_flag']))
    # Prepare data to send
    return text

print(decrypt_flag(scalar_multiplication(B, private_key).x, encrypted_flag))













# Other ideas that didn't finish in a solution:

# Given that the condition of a point being on the ellipse is x**2 - D*y**2 = 1, we have that the x coordinate of P+P is
# P.x**2 + D*P.y**2 = (1 + D*P.y**2) + D*P.y**2 = 1 + 2*D*P.y**2. Therefore, the x coordinate of P+P depends only on the 
# y coordinate of P. Therefore, we can find (a list of candidates of) P from  P+P by finding ±P.y from (P+P).x.

# To add two points P and Q, you first apply the function f(x,y) = (x,sqrt(-D)*y), which maps the ellipse to the circle.
# Then, multiply f(P) and f(Q) as complex points in the circle, and then apply f^{-1}(x,y) = (x, y/sqrt(-D)). Therefore
# point multiplication in the ellipse can be seen as f^{-1}(f(P)*f(Q)), where the multiplication is the usual multiplication
# in the complex plane in F_p.
# Unluckily, sqrt(-D) doesn't exist mod p.

# Another thing to consider is that we can consider the set as a hiperbola of equation x^2 - y^2 = 1 (after applying the map (x,y) -> (x,sqrt(D)*y)).
# Having this hiperbola in mind, adding two points can be seen as P+Q = (P.x*Q.x + P.y*Q.y, P.x*Q.y + P.y*Q.x) = ( {P*conj(Q)}.x , {P*Q}.y ).
# Therefore P + conj(Q) = ( {P*Q}.x , {P*conj(Q)}.y )
# Now, since both the x and y coordinate uniquely determine at most two points, adding two points can be seen as "multiply the points as if they where
# complex numbers, take the y coordinate and complete the other x coordinate given a criteria".

# P+P = (x^2 + y^2 , 2xy). O sea que (P+P).x + (P+P).y = (P.x + P.y)^2 


