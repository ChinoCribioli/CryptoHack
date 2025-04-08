###  SOURCE CODE

from Crypto.Util.number import getPrime
import random
# from utils import listener

FLAG = 'crypto{???????????????????????????????????}'

class Challenge():
    def __init__(self):
        self.no_prompt = True
        self.q = getPrime(512)
        self.x = random.randint(2, self.q)

        self.g = None
        self.n = None
        self.h = None

        self.current_step = "SHARE_PRIME"

    def check_params(self, data):
        self.g = int(data['g'], 16)
        self.n = int(data['n'], 16)
        if self.g < 2:
            return False
        elif self.n < 2:
            return False
        elif pow(self.g,self.q,self.n) != 1:
            return False
        return True

    def check_secret(self, data):
        x_user = int(data['x'], 16)
        if self.x == x_user:
            return True
        return False

    def challenge(self, your_input):
        if self.current_step == "SHARE_PRIME":
            self.before_send = "Prime generated: "
            self.before_input = "Send integers (g,n) such that pow(g,q,n) = 1: "
            self.current_step = "CHECK_PARAMS"
            return hex(self.q)

        if self.current_step == "CHECK_PARAMS":
            check_msg = self.check_params(your_input)
            if check_msg:
                self.x = random.randint(0, self.q)
                self.h = pow(self.g, self.x, self.n)
            else:
                self.exit = True
                return {"error": "Please ensure pow(g,q,n) = 1"}

            self.before_send = "Generated my public key: "
            self.before_input = "What is my private key: "
            self.current_step = "CHECK_SECRET"

            return hex(self.h)

        if self.current_step == "CHECK_SECRET":
            self.exit = True
            if self.check_secret(your_input):
                return {"flag": FLAG}
            else:
                return {"error": "Protocol broke somewhere"}

        else:
            self.exit = True
            return {"error": "Protocol broke somewhere"}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13403)


### SOLUTION

# If we want g^q = 1 mod n, we must have q | phi(n). Therefore, we propose n = q^2, since phi(q^2) = (q-1)*q. For a generator, we can consider a number of order phi(n)
# (we assume 2 works) and raise it to the (q-1)-th power, which will result in an element of order phi(n)/(q-1) = q. So g = 2^{q-1} mod n.
# Now, since n = q^2, we can take reminders modulo n and take modulo q (this is well defined since q | q^2). Since phi(q) = q-1, we have that g = 2^{q-1} = 1 mod q.
# Therefore, g = kq + 1 mod n, for 0 <= k < q. Now, g^x = (kq + 1)^x = xkq + 1 mod n, since any other term in the expansion of (kq + 1)^x will have a q^2 factor, which is 0 mod n.
# So we can recover x from h by doing (h-1)/(kq). We have to be careful here since we cannot divide by q modulo n. Since k < q, we can multiply by k^{-1} mod n, and then simply
# divide by q as integers. Thus, we first calculate (h-1)/k as a reminder of n, and then divide that by q as integers.

import socket
import json

HOST = "socket.cryptohack.org"
PORT = 13403 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(10000), "\n")
    response = socket.recv(10000)
    q = int(response.split(b'"')[1], 16)
    n = q**2 
    phi_n = q*(q-1)
    g = pow(2,q-1,n)

    params = {
        'g': hex(g),
        'n': hex(n)
    }
    socket.send(json.dumps(params).encode('utf-8'))

    print(socket.recv(10000), "\n")
    response = socket.recv(10000)
    h = int(response.split(b'"')[1], 16)
    print(f"h: {h}\n")
    assert(g%q == 1)
    k = (g-1)//q
    secret = (h-1)//q
    secret *= pow(k,-1,q)
    secret %= q
    assert(pow(g,secret,n) == h)
    answer = {
        'x': hex(secret)
    }
    socket.send(json.dumps(answer).encode('utf-8'))

    print(socket.recv(10000), "\n")

