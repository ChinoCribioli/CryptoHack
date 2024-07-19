from random import randint
import copy

def TS(a,p): # Finds r such that r^2 = a (mod p)
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
	assert(pow(r,2,p) == a)
	return r