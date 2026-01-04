### SOURCE


#!/usr/bin/env python3

# from utils import listener

FLAG = 'crypto{????????????????????????????????????}'


def generate_basis(n):
    basis = [True] * n
    for i in range(3, int(n**0.5)+1, 2):
        if basis[i]:
            basis[i*i::2*i] = [False]*((n-i*i-1)//(2*i)+1)
    return [2] + [i for i in range(3, n, 2) if basis[i]]


def miller_rabin(n, b):
    """
    Miller Rabin test testing over all
    prime basis < b
    """
    basis = generate_basis(b)
    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for b in basis:
        x = pow(b, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def lizzies_little_window(a, p):
    if p < 1 or a < 1:
        return "[*] Error: Please, I will only accept positive integers."
    if p.bit_length() <= 600:
        return "[*] Error: Of all the primes, you choose to send me one so small?"
    if p.bit_length() > 900:
        return "[*] Error: I do wonder what're you trying to prove with a prime so big?"
    if not miller_rabin(p, 64):
        return "[*] Error: Sir, do you know what a prime number is?"
    if p < a:
        return "[*] Error: I'm sorry, but your base must be coprime to p"
    x = pow(a, p-1, p)
    return f"[*] Success: You passed all my tests! Here's the first byte of my flag: {FLAG[:x]}"


class Challenge():
    def __init__(self):
        self.before_input = "Oh Mr. Darcy, send me your primes!\n"

    def challenge(self, your_input):
        if not 'prime' in your_input or not 'base' in your_input:
            return {"error": "Please send a prime and a base to the server."}

        p = your_input['prime']
        a = your_input['base']
        return {"Response": lizzies_little_window(a, p)}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13385)


### SOLUTION

# We are going to implement Arnault's Method to construct pseudoprimes to a set of fixed bases.
# This method is outlined starting on page 25 of the paper "Prime and Prejudice: Primality Testing Under Adversarial Conditions",
# which can be found at https://eprint.iacr.org/2018/749.pdf or in this repository.
# The fixed set of bases will be the primes smaller than 64, given that the 'generate_basis' method 
# returns that set to use as witnesses for the Miller-Rabin primality test.

from Crypto.Util.number import getPrime, isPrime, inverse, bytes_to_long, long_to_bytes

def legendre_symbol(a,p):
    # Since p will not always be prime and a will, I prefer to calculate the symbol using the law of quadratic reciprocity.
    reciprocal = pow(p, (a-1)//2, a)
    if reciprocal == a-1:
        reciprocal = -1
    assert(reciprocal**2 <= 1)
    sign = (-1)**((a-1)*(p-1)//4)
    return reciprocal if sign == 1 else -reciprocal

def calculate_S_a(a):
    # Since 2 is not odd, we cannot use the legendre symbol, so we return this case separately
    if a == 2:
        return set([3,5])
    S_a = set()
    for p in range(3,4*a,2): # We exclude p = 1 or 2 because every reminder mod 1 and 2 are quadratic residues.
        if legendre_symbol(a,p) == -1:
            S_a.add(p)
    return S_a

test_S_a = [2,3,5,7,11,13,17,19,23,29]
correct = {
    2 : [3, 5],
    3 : [5, 7],
    5 : [3, 7, 13, 17],
    7 : [5, 11, 13, 15, 17, 23],
    11 : [3, 13, 15, 17, 21, 23, 27, 29, 31, 41],
    13 : [5, 7, 11, 15, 19, 21, 31, 33, 37, 41, 45, 47],
    17 : [3, 5, 7, 11, 23, 27, 29, 31, 37, 39, 41, 45, 57, 61, 63, 65],
    19 : [7, 11, 13, 21, 23, 29, 33, 35, 37, 39, 41, 43, 47, 53, 55, 63, 65, 69],
    23 : [3, 5, 17, 21, 27, 31, 33, 35, 37, 39, 45, 47, 53, 55, 57, 59, 61, 65, 71, 75, 87, 89],
    # The paper says 61 is not in S_29, but 29 is a non-residue mod 61, so I guess this is a mistake.
    29 : [3, 11, 15, 17, 19, 21, 27, 31, 37, 39, 41, 43, 47, 55, 61, 69, 73, 75, 77, 79, 85, 89, 95, 97, 99, 101, 105, 113],}

for a in test_S_a:
    try:
        assert(sorted(calculate_S_a(a)) == correct[a])
    except:
        print(f"Error: Incorrect S_{a}")

def gcd(a,b):
    if a > b:
        return gcd(b,a)
    if a == 0:
        return b 
    return gcd(b%a, a)

# Chinese Reminder Theorem implementation
def crt(constraints):
	if len(constraints) == 1:
		return constraints[0]
	(r1,m1) = constraints[-1]
	(r2,m2) = constraints[-2]
	assert(gcd(m1,m2) == 1)
	constraints = constraints[:-2]
	newmod = m1*m2
	constraints.append(( (r1*m2*pow(m2,-1,m1) + r2*m1*pow(m1,-1,m2)) % newmod , newmod))
	return crt(constraints)

# This method is to check whether, given the coefficients k, the p1 is useful
def is_valid_p1(p1, k):
    p = [k_i*(p1-1) + 1 for k_i in k]
    for p_i in p:
        if not isPrime(p_i):
            return False
    n = 1 
    for p_i in p:
        n *= p_i
    if n.bit_length() <= 600:
        return False 
    if n.bit_length() > 900:
        print("Error: Reached upper bound and didn't find a suitable p1")
        return False
    return miller_rabin(n,64)

def arnaults_method(b):
    bases = generate_basis(b)
    max_bit_length = bases[-1].bit_length()
    # For now, we will use fixed primes
    k = [1, 101, 193]
    k = [1, 67, 157]
    # If we want to generate new random k coefficients, uncomment the next two lines
    # k = [1, getPrime(max_bit_length+1), getPrime(max_bit_length+2)]
    # print(f"k: {k}")
    S = []
    for a in bases:
        S_a = calculate_S_a(a)
        aux_S_a = S_a
        for k_i in k:
            S_a = S_a.intersection({ inverse(k_i,4*a)*(p+k_i-1) % (4*a) for p in aux_S_a})
        S.append(S_a)

    # The paper says that the initial conditions are k_2^{-1} mod k_3 and k_2^{-1} mod k_2,
    # but in the example it says they are -k_2^{-1} mod k_3 and -k_3^{-1} mod k_2.
    # We tried both and only the latter works, so I guess this is another mistake in the article.
    conditions = [(inverse(-k[1],k[2]), k[2]), (inverse(-k[2],k[1]), k[1])]

    # We check wether the posible sets enable us a consistent congruence mod 4.
    # Since all the other constraints' moduli are distinct primes, this would be the only
    # thing preventing us to find a suitable condition that meets all the modular constraints.
    isOnly1 = False
    isOnly3 = False
    for S_a in S:
        has1 = False
        has3 = False
        for p in S_a:
            if p % 4 == 1:
                has1 = True
            else:
                has3 = True
        if not has3:
            isOnly1 = True
        if not has1:
            isOnly3 = True
    if isOnly1 and isOnly3:
        print("It is not posible to achieve a consistent reminder mod 4")
        return
    rem_mod4 = 0
    if isOnly1:
        conditions.append((1,4))
        rem_mod4 = 1
    else:
        conditions.append((3,4))
        rem_mod4 = 3

    # Now, we choose the reminders mod each prime of the bases 
    for i in range(1,len(bases)): # We ignore the case where a = 2 because we don't have to add a constraint modulo 2. There is a constraint mod 4 already
        a = bases[i]
        for z_a in S[i]:
            if z_a % 4 == rem_mod4:
                conditions.append((z_a % a, a))
                break

    final_constraint = crt(conditions)
    p1 = final_constraint[0]
    m = final_constraint[1]
    # print(f"Initial modular constraints to p1:\nReminder: {p1}\nModulus: {m}")

    p1 += m * (1<<(198 - m.bit_length()))
    while not is_valid_p1(p1, k):
        p1 += m

    n = 1 
    for k_i in k:
        n *= k_i*(p1-1) + 1
    return (n, p1)


ans = arnaults_method(64)
# print("ans: ", ans)
# print(lizzies_little_window(ans[1], ans[0]))

# The previous work gives us the following example to break the miller-rabin test with bases up to 64:
n = 675120653215215366971168932927212535437886754652782709639545215053558915287650580356411571552315077841768329303125077947144304453537879719881261427941296167974488202254382014850157853 
p1 = 400376869598487807828218303597075999330134785095577872328557 

### CONECTION

import socket
import json

HOST = "socket.cryptohack.org"
PORT = 13385 

from pwn import *
import json

r = remote(HOST, PORT)

def json_send(message):
    request = json.dumps(message).encode()
    r.sendline(request)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(10000), "\n")

    message = {
        'prime': n,
        'base': p1
    }
    socket.send(json.dumps(message).encode('utf-8'))

    print(socket.recv(10000), "\n")

