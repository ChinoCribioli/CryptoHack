n = 27772857409875257529415990911214211975844307184430241451899407838750503024323367895540981606586709985980003435082116995888017731426634845808624796292507989171497629109450825818587383112280639037484593490692935998202437639626747133650990603333094513531505209954273004473567193235535061942991750932725808679249964667090723480397916715320876867803719301313440005075056481203859010490836599717523664197112053206745235908610484907715210436413015546671034478367679465233737115549451849810421017181842615880836253875862101545582922437858358265964489786463923280312860843031914516061327752183283528015684588796400861331354873
e = 16
ct = 11303174761894431146735697569489134747234975144162172162401674567273034831391936916397234068346115459134602443963604063679379285919302225719050193590179240191429612072131629779948379821039610415099784351073443218911356328815458050694493726951231241096695626477586428880220528001269746547018741237131741255022371957489462380305100634600499204435763201371188769446054925748151987175656677342779043435047048130599123081581036362712208692748034620245590448762406543804069935873123161582756799517226666835316588896306926659321054276507714414876684738121421124177324568084533020088172040422767194971217814466953837590498718

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

# IMPORTANT FACT: I asked sage to factorize n and it gave me that it is prime. So we can use TS to find square roots.
# First, notice that gcd(n-1,16) = 8, so if I have x^16, I can find (a,b) such that 16*a + (n-1)*b = 8 and recover 
# (x^16)^a = x^{16a} * 1 = x^{16a} * x^{n-1}^b = x^{16*a + (n-1)*b} = x^8.
# This can be done because the multiplicative group of F_n has order n-1, which is multiple of 8 but not 16.
# So the morphism x -> x^2 is an isomorphism in the subgroup of powers of 8.

g,a,b = extendedEucldeanAlgorithm(16,n-1)
assert(g == 8)
assert(a*16+b*(n-1) == 8)

a = pow(ct,a,n)
assert(pow(a,2,n) == ct)

# Now, I must calculate every possible 8th root of a, which can be done by applying TS repeatedly.
# For this, I first find one 8th root of a, and then multiply it by every 8th root of unity.

a = Tonelli_Shanks(a,n)
a = Tonelli_Shanks(a,n)
a = Tonelli_Shanks(a,n)

assert(pow(a,16,n) == ct)

# Now I calculate the 8th roots of unity

roots_of_1 = [1, n-1]

last_processed = 1
for _ in range(2):
	new_roots = []
	for i in range(last_processed,len(roots_of_1)):
		new_root = Tonelli_Shanks(roots_of_1[i], n)
		assert(pow(new_root, 8, n) == 1)
		new_roots.append(new_root)
		new_roots.append(n-new_root)
	last_processed = len(roots_of_1)
	roots_of_1 += new_roots

assert(len(roots_of_1) == 8)

candidates = [(a*root)%n for root in roots_of_1]

assert(n >> 2047 == 1)
assert(n >> 2048 == 0)

for cand in candidates:
	assert(pow(cand,16,n) == ct)
	print(cand.to_bytes(256, 'big'))

