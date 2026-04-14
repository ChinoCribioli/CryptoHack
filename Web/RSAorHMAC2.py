# If I have a header h, body b and priv_key s
# The HS256 signature is SHA256(h || b || s)
# The RS256 signature is RSA_Sign(SHA256(h||b), s)

# Thus, if I can find the public key corresponding to the RSA key pair of s, I can sign my malicious JWT with HS256 and it will be accepted.
# Without that pk it will be infeasible to try to forge the HS256 signature since it will mean finding a collision of SHA256. So I have to find pk.

# Now, this pk, is a .pem file that depends only on the exponent e and the modulus n. We assume that e = 65537 since it is the standard.
# Thus, we have to find n. Now, since it is the modulus, we know that n is greater than any signature we obtain from the 'create_session' endpoint.
# So we can use this as an oracle to get any number of signatures we want and bound n.

from Crypto.PublicKey import RSA
# from Crypto.Util.number import getPrime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def serialize_pem_key(n: int, e: int = 65537, output_file: str = "Web/rsa-or-hmac-2-public.pem"):
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )    

    with open(output_file, "wb") as f:
        f.write(pem)
    
    print(pem.decode())

def parse_rsa_public_pem(filename: str = "Web/rsa-or-hmac-2-public.pem"):
    with open(filename, "r") as f:
        pem_data = f.read()

    key = RSA.import_key(pem_data)

    n = key.n
    e = key.e

    return n, e

# serialize_pem_key(getPrime(20)*getPrime(23))
# print(parse_rsa_public_pem())

import base64

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

import json
import hashlib

def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def jwt_hash_for_rs256(username: str) -> int:
    header = {'alg': 'RS256', 'typ': 'JWT'}
    payload = {'username': username, 'admin': False}

    header_b64 = base64url(json.dumps(header, separators=(',',':')).encode())
    payload_b64 = base64url(json.dumps(payload, separators=(',',':')).encode())

    signing_input = f"{header_b64}.{payload_b64}"

    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    hash = SHA256.new(signing_input.encode()) # encode('ascii') ??
    padded = pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(hash, 256)
    hash_int = int.from_bytes(padded, "big")

    # digest = hashlib.sha256(signing_input.encode()).digest()
    # hash_int = int.from_bytes(digest, "big")

    return (hash_int, signing_input)

import requests
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


import random
import string
characters = string.ascii_letters + string.digits

def gen_random_string(l = 10):
    return ''.join(random.choices(characters, k=l))


import gmpy2
from math import gcd

def recover_n(num_samples=2, e = 65537):
    values = []

    for _ in range(num_samples):
        s = gen_random_string()
        (a, session_info) = jwt_hash_for_rs256(s)
        session_jwt = create_session_and_obtain_jwt(s)
        session_parts = session_jwt.split('.')
        assert(session_info == f"{session_parts[0]}.{session_parts[1]}")
        x = int_signature_from_jwt(session_jwt)

        x = gmpy2.mpz(x)
        a = gmpy2.mpz(a)
        print(f"a: {a}\nx: {x}")

        val = pow(x, e)
        print(f"val bit_length: {val.bit_length()}")

        diff = val - a
        values.append(diff)

    # calculate gcd
    n = values[0]
    for v in values[1:]:
        n = gmpy2.gcd(n, v)

    return n


# n = int(recover_n(5))
n = 30119723976045246500887959920897642376905514522104705876695572516818975656665827754462226597973931127004963194508794779495518118035029841228002850562126612806174354282950756669656076190799693066363785733231859172664786298352294594850108982261525326147060353679479844558827458650965802914077525964824412575118501773357860374735206849817271524812002047307305597712628593230518376740507962518305824812671107459660525177087958778694060270468673690931325503094560625544374011735643694318730778241846282742819834483180624645324880062782719575587058519516842316778261924794437716972651884728674806670910304714203419102131413
print(f"n: {n}")
assert(n == 30119723976045246500887959920897642376905514522104705876695572516818975656665827754462226597973931127004963194508794779495518118035029841228002850562126612806174354282950756669656076190799693066363785733231859172664786298352294594850108982261525326147060353679479844558827458650965802914077525964824412575118501773357860374735206849817271524812002047307305597712628593230518376740507962518305824812671107459660525177087958778694060270468673690931325503094560625544374011735643694318730778241846282742819834483180624645324880062782719575587058519516842316778261924794437716972651884728674806670910304714203419102131413)


serialize_pem_key(n)
assert(parse_rsa_public_pem()[0] == n)

with open('Web/rsa-or-hmac-2-public.pem', 'rb') as f:
   PUBLIC_KEY = f.read()

print("pubKey:")
print(PUBLIC_KEY)

import jwt
encoded = jwt.encode({'username': 'hola', 'admin': True}, PUBLIC_KEY, algorithm='HS256')
print(f"forged jwt: {encoded}")
decoded = jwt.decode(encoded, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
print(decoded)



# n = 30096249942681484329654519953485866783863444473812858930726522962770050300159749568703908449771989466816004339531489467614079230208259604211603043085550566177214318913761629594129027609667020120585305092219778254121504601589168868471617050825114792584050775186608539273673697857638163396374797520482195366079163107064138679136473483163620155828280343003056926361310377660526407964993959229504458985564422100868953257202915062680746308235150920189812952257280065729439227943387447720293521241469919373915525163182245682720471505135783175242512359233696093961963945764543996936467096240741712414329261534413033631786781 
# while True:
#     candidate = int_signature_from_jwt(create_session_and_obtain_jwt())
#     print(candidate.bit_length())
#     if candidate > n:
#         print(candidate)
#         n = candidate


# Now, I have unbounded access to an oracle that recieves some b and returns SHA256(b)^s mod n. So I have access to an oracle that gives me both
# x and x^s mod n. 

# pub_key = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAvoOtsfF5Gtkr2Swy0xzuUp5J3w8bJY5oF7TgDrkAhg1sFUEaCMlR\nYltE8jobFTyPo5cciBHD7huZVHLtRqdhkmPD4FSlKaaX2DfzqyiZaPhZZT62w7Hi\ngJlwG7M0xTUljQ6WBiIFW9By3amqYxyR2rOq8Y68ewN000VSFXy7FZjQ/CDA3wSl\nQ4KI40YEHBNeCl6QWXWxBb8AvHo4lkJ5zZyNje+uxq8St1WlZ8/5v55eavshcfD1\n0NSHaYIIilh9yic/xK4t20qvyZKe6Gpdw6vTyefw4+Hhp1gROwOrIa0X0alVepg9\nJddv6V/d/qjDRzpJIop9DSB8qcF1X23pkQIDAQAB\n-----END RSA PUBLIC KEY-----\n"
# with open('Web/rsa-or-hmac-2-private.pem', 'rb') as f:
#    PRIVATE_KEY = f.read()
# # Public key generated using: openssl rsa -RSAPublicKey_out -in rsa-or-hmac-2-private.pem -out rsa-or-hmac-2-public.pem
# with open('Web/rsa-or-hmac-2-public.pem', 'rb') as f:
#    PUBLIC_KEY = f.read()
#
# print("sk:", PRIVATE_KEY)
# print("pk:", PUBLIC_KEY)
#
# import jwt
# import base64
# import json
#
# token = jwt.encode({"admin": True}, pub_key, algorithm="HS256")
# token_parts = token.split('.')
# print(base64.b64decode(token_parts[0]))
# # print(base64.urlsafe_b64decode(token_parts[1]))
# print(base64.b64decode(token_parts[2]))
# # print(jwt.decode(token,pub_key, algorithms=["HS256"]))
# print(jwt.get_unverified_header(token))
# print(jwt.decode(token, options={"verify_signature": False}))

# Running this code by itself throws the following error:

# File "/usr/lib/python3/dist-packages/jwt/algorithms.py", line 189, in prepare_key
#     raise InvalidKeyError(
# jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.

# Therefore, I run 'sudo nvim /usr/lib/python3/dist-packages/jwt/algorithms.py' and comment the whole if that contains line 189.
# After doing that, I run the code again and this time it throws the malicious token we want.

