### SOURCE

from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
import math
# from utils import listener
# from secrets import N, E, D

FLAG = "crypto{??????????????????}"


# key = RSA.construct((N, E, D))
# sig_scheme = pkcs1_15.new(key)


class Challenge():
    def __init__(self):
        self.before_input = "Primality checking is expensive so I made a service that signs primes, allowing anyone to quickly check if a number is prime\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            p = int(msg["prime"])
            if p.bit_length() > 1024:
                return {"error": "The prime is too large."}
            if not isPrime(p):
                return {"error": "You must specify a prime."}

            hash = MD5.new(long_to_bytes(p))
            sig = sig_scheme.sign(hash)
            return {"signature": sig.hex()}

        elif msg["option"] == "check":
            p = int(msg["prime"])
            sig = bytes.fromhex(msg["signature"])
            hash = MD5.new(long_to_bytes(p))
            try:
                sig_scheme.verify(hash, sig)
            except ValueError:
                return {"error": "Invalid signature."}

            a = int(msg["a"])
            if a < 1:
                return {"error": "`a` value invalid"}
            if a >= p:
                return {"error": "`a` value too large"}
            g = math.gcd(a, p)
            flag_byte = FLAG[:g]
            return {"msg": f"Valid signature. First byte of flag: {flag_byte}"}

        else:
            return {"error": "Unknown option."}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13392)


### SOLUTION


# First, we consider a collision that I took from stackexchange. The plaintexts have to be short (1 block) since the numbers we get from them
# must have a bit_length <= 1024.

m1 = bytes.fromhex("0e306561559aa787d00bc6f70bbdfe3404cf03659e704f8534c00ffb659c4c8740cc942feb2da115a3f4155cbb8607497386656d7d1f34a42059d78f5a8dd1ef")
m2 = bytes.fromhex("0e306561559aa787d00bc6f70bbdfe3404cf03659e744f8534c00ffb659c4c8740cc942feb2da115a3f415dcbb8607497386656d7d1f34a42059d78f5a8dd1ef")

h1 = MD5.new(m1).hexdigest()
h2 = MD5.new(m2).hexdigest()
assert(h1==h2)

# Then, since we have m1 and m2 such that MD5(m1) == MD5(m2), we know that MD5(m1 + b) == MD5(m2 + b) for any bytearray b since m1 and m2 have 
# a length of exactly one 512-bit block.
# Therefore, we can try different values of b until one of m1+b or m2+b is prime and the other is not. Since they hash to the same, they have 
# the same signature. So we can sign the prime one and then check the composite one to get the flag.

# For the composite number, I want a factor greater to 50 to get all the flag characters.
def goodFactor(n):
    for i in range(50,100):
        if n % i == 0:
            return i
    return 0

for i in range(1,1000000):
    candidate1 = m1 + long_to_bytes(i)
    candidate2 = m2 + long_to_bytes(i)
    h1 = MD5.new(candidate1).hexdigest()
    h2 = MD5.new(candidate2).hexdigest()
    assert(h1 == h2)
    p = bytes_to_long(candidate1)
    n = bytes_to_long(candidate2)
    assert(p.bit_length() <= 1024)
    if isPrime(p) and goodFactor(n):
        print("p: ", p)
        print("n: ", n)
        print("factor of n: ", goodFactor(n), "\n")
        break

import socket
import json

def json_recv(line):
    return json.loads(line.decode())


HOST = "socket.cryptohack.org"
PORT = 13392 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(10000), "\n")

    query = {
        "option": "sign",
        "prime": str(p)
    }
    socket.send(json.dumps(query).encode('utf-8'))

    response = json_recv(socket.recv(10000))

    answer = {
        "option": "check",
        "prime": str(n),
        "signature": response["signature"],
        "a": str(83)
    }
    socket.send(json.dumps(answer).encode('utf-8'))

    response = json_recv(socket.recv(10000))
    print(response)

