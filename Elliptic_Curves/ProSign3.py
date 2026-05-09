###   SOURCE

#!/usr/bin/env python3

import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa.ecdsa import Public_key, Private_key, Signature, generator_192
# from utils import listener
from datetime import datetime
from random import randrange

FLAG = "crypto{?????????????????????????}"
g = generator_192
n = g.order()

class Challenge():
    def __init__(self):
        self.before_input = "Welcome to ProSign 3. You can sign_time or verify.\n"
        secret = randrange(1, n)
        self.pubkey = Public_key(g, g * secret)
        self.privkey = Private_key(self.pubkey, secret)

    def sha1(self, data):
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        return sha1_hash.digest()

    def sign_time(self):
        now = datetime.now()
        m, n = int(now.strftime("%m")), int(now.strftime("%S"))
        current = f"{m}:{n}"
        msg = f"Current time is {current}"
        hsh = self.sha1(msg.encode())
        sig = self.privkey.sign(bytes_to_long(hsh), randrange(1, n))
        return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}

    def verify(self, msg, sig_r, sig_s):
        hsh = bytes_to_long(self.sha1(msg.encode()))
        sig_r = int(sig_r, 16)
        sig_s = int(sig_s, 16)
        sig = Signature(sig_r, sig_s)

        if self.pubkey.verifies(hsh, sig):
            return True
        else:
            return False

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'sign_time':
            signature = self.sign_time()
            return signature

        elif your_input['option'] == 'verify':
            msg = your_input['msg']
            r = your_input['r']
            s = your_input['s']
            verified = self.verify(msg, r, s)
            if verified:
                if msg == "unlock":
                    self.exit = True
                    return {"flag": FLAG}
                return {"result": "Message verified"}
            else:
                return {"result": "Bad signature"}

        else:
            return {"error": "Decoding fail"}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13381)

#	SOLUTION

HOST = "socket.cryptohack.org"
PORT = 13381

# If we notice in the implementation that the random number k is chosen in the range [1,n], and that n < 60
# (because it is the number in the seconds marker in the current time 'now'), we can brute force the secret value k given that
# we are given with r, which is the x coordinate of kG.

x_coordinates = {}
for i in range(1,60):
	x_coordinates[(i*generator_192).x()] = i
	# Now, given r, we know that the respective k is x_coordinates[r]

# Now, a given a valid signature, we know that s = k^{-1}(H(m)+dr) must hold. Therefore, given a signature and having k,
# we can extract the secret d by doing sk - H(m) = dr ---> (sk - H(m))/r = d

# SPANISH GIBBERISH (an approach I had before. It is incorrect but I don't want to erase it and I'm too lazy to translate it):
# s = k^{-1}(H(m)+dr)   -----> s^{-1} = k(H(m)+dr)^{-1}
# Me dan una firma (r,s) tal que H(m)s^{-1} + drs^{-1} = k, con m = "La hora es x".
# O sea que cumple que  H(m)s{-1}*P+rs{-1}*Q = kP, que es igual a
# H(m)*P + r*Q = s(kP)
# Observacion: Dado r no puedo recuperar k pero si kP (pues saber la coordenada x te da o bien kP o -kP, y podes probar los dos).
# Ahora, quiero s' tal que H(m')*P + r*Q = s'(kP) donde m' = "unlock".
# Si resto, tengo (H(m)-H(m'))*P = (s-s')(kP). Tengo s, (H(m)-H(m')) y kP
# H(m)*P - s*kP = H(m')*P - s'*(kP)
# Si hago q = H(m')/H(m) y mando (q*r,q*s), eso anda? No porque estas modificando el r pero no el k, que estan  relacionados.


import socket
import json

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    ch = Challenge()
    target_hash = ch.sha1("unlock".encode())

    socket.connect((HOST, PORT))
    
    print(socket.recv(10000), "\n")
    challenge = {
    	'option': 'sign_time',
    }
    socket.send(json.dumps(challenge).encode('utf-8'))
    response = json.loads(socket.recv(10000))
    print(response)
    # socket.send(json.dumps(challenge).encode('utf-8'))
    # signature = json.loads(socket.recv(10000))
    m1 = response['msg']
    h1 = ch.sha1(m1.encode())
    r = int(response['r'], 16)
    s = int(response['s'], 16)
    k = x_coordinates[r]
    h1_int = bytes_to_long(h1)
    d = (s*k - h1_int) * pow(r, -1, g.order())
    d %= g.order()

    m2 = "unlock"
    h2 = ch.sha1(m2.encode())
    h2_int = bytes_to_long(h2)

    # s = k^{-1}(H(m)+dr)
    new_s = (h2_int + d*r) * pow(k, -1, g.order())
    new_s %= g.order()
    challenge = {
    	'option': 'verify',
    	'msg': "unlock",
    	'r': hex(r),
    	's': hex(new_s)
    }
    socket.send(json.dumps(challenge).encode('utf-8'))
    print(socket.recv(10000), "\n")
