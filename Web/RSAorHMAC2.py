# If I have a header h, body b and priv_key s
# The HS256 signature is SHA256(h || b || s)
# The RS256 signature is RSA_Sign(SHA256(h||b), s)

# Thus, if I can find the public key corresponding to the RSA key pair of s, I can sign my malicious JWT with HS256 and it will be accepted.
# Without that pk it will be infeasible to try to forge the HS256 signature since it will mean finding a collision of SHA256. So I have to find pk.

# Now, this pk, is a .pem file that depends only on the exponent e and the modulus n. We assume that e = 65537 since it is the standard.
# Thus, we have to find n. Now, since it is the modulus, we know that n is greater than any signature we obtain from the 'create_session' endpoint.
# So we can use this as an oracle to get any number of signatures we want and bound n.

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime

def serialize_pem_key(n: int, e: int = 65537, output_file: str = "Web/rsa-or-hmac-2-public.pem"):
    key = RSA.construct((n, e))
    
    pem = key.export_key(format="PEM")
    
    # Escribe en el archivo
    with open(output_file, "wb") as f:
        f.write(pem)
    
    print(pem)

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
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"username": username, "admin": False}

    header_b64 = base64url(json.dumps(header, separators=(',',':')).encode())
    payload_b64 = base64url(json.dumps(payload, separators=(',',':')).encode())

    signing_input = f"{header_b64}.{payload_b64}"

    digest = hashlib.sha256(signing_input.encode()).digest()
    hash_int = int.from_bytes(digest, "big")

    return hash_int

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

# x1 = jwt_hash_for_rs256("a")
# x2 = jwt_hash_for_rs256("b")
#
# s1 = int_signature_from_jwt(create_session_and_obtain_jwt("a"))
# s2 = int_signature_from_jwt(create_session_and_obtain_jwt("b"))

# from math import gcd
#
# print(gcd(x2-x1, s1-s2))

import random
import string
characters = string.ascii_letters + string.digits

def gen_random_string(l = 100):
    return ''.join(random.choices(characters, k=l))

real_n = 357

# n = 3425857033280044914259085670712728675552904168873734088180300071832242196744850195411499785716960160133385039072657452525635067756239590369863290664551330431156681891604435821390881006671902601932176479606099211077402385185556711332328797693769946317450561388682777410600840836594619855276519432184902415837713340176617745778886309141883273468139197127277221663250354818846746191176521155357431087560269161809368511360403750713103822323557576050230271470677644089048291433474038474093449548902173483664414997470215475946172748346979365495241718859267006233893078431217389164683080609429916813844145942577115557304673
# t = 2048
n = 1 
t = 2
mod = 2**(t+1)
# while t < 2048:
while t < 9:
    pow2 = mod // 2
    s = gen_random_string()
    a = jwt_hash_for_rs256(s)
    # x = int_signature_from_jwt(create_session_and_obtain_jwt(s))
    x = pow(a,65537,real_n)
    r = ( pow(a, 65537, mod) - x ) % mod
    if r % 2 == 0:
        continue
    k_t = ( r * pow(n, -1, pow2) ) % (pow2)
    assert(k_t % 2 != 0)

    candidates = []
    for i in range(2):
        for j in range(2):
            if ((i*pow2 + k_t)*(j*pow2 + n)) % mod == r:
                candidates.append((i,j))

    if len(candidates) != 1:
        print(f"retry. n:{n}, t:{t}")
        continue
    n += candidates[0][1]*pow2

    t += 1 
    mod *= 2 


    # candidate = ((r - k_t*n) % mod) * pow(k_t, -1, mod)
    # candidate %= mod
    # if candidate == 0 or candidate == pow2:
    #     # the next bit of k was 0
    #     pass 
    # else:
    #     # the next bit of k was 1
    #     k = k_t + pow2
    #     candidate = ((r - k*n) % mod) * pow(k, -1, mod)
    #     candidate %= mod
    #     assert(candidate == 0 or candidate == pow2)
    #
    # if candidate == 0:
    #     # the next bit of n is 0 
    #     t += 1 
    #     mod *= 2 
    # else:
    #     # the next bit of n is 1 
    #     n += pow2
    #     t += 1 
    #     mod *= 2

    print(t, n)

assert(n == real_n)

# serialize_pem_key(n)
assert(parse_rsa_public_pem()[0] == n)

with open('Web/rsa-or-hmac-2-public.pem', 'rb') as f:
   PUBLIC_KEY = f.read()

import jwt
encoded = jwt.encode({'username': 'hola', 'admin': True}, PUBLIC_KEY, algorithm='HS256')
print(encoded)
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

