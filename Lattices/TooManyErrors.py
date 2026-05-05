### SOURCE

from Crypto.Random.random import getrandbits
import random
# from utils import listener

SEED = getrandbits(32)
FLAG = b'crypto{????????????????????}'
q = 127


class Challenge():
    def __init__(self):
        self.before_input = f"Welcome to the LWE sample generator! Retrieve a sample using the 'get_sample' option, or reset the distribution using the 'reset' option.\n"
        self.rand = random.Random(SEED)

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input["option"] == "reset":
            self.rand.seed(SEED)
            return {"success": "The distribution has been reset"}

        elif your_input["option"] == "get_sample":
            a = []
            for i in range(len(FLAG)):
                a.append(self.rand.randint(0, q - 1))

            e = self.rand.randint(-1, 1)

            self.rand.seed(getrandbits(32))
            if self.rand.randint(0, 1):
                a[self.rand.randint(0, len(a) - 1)] = self.rand.randint(0, q - 1)

            b = 0
            for (i, j) in zip(a, FLAG):
                b += i * j
            b += e
            b %= q

            return {"a": a, "b": b}

        else:
            return {"error": "Invalid option"}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
# listener.start_server(port=13390)

### SOLUTION

# For this challenge, we must note that, after seeding the Random Number Generator, the outputs of 'rand' are deterministic. Thus, after a 'reset' query, the values of a, b and e are fixed
# since the SEED variable is fixed. This is up until the line where we seed the RNG with a new 'getrandbits(32)', where half of the times the server modifies a value of a before sending it.
# The first step is to retrieve the values of a and b that are default before this last modification step. That way we can identify, in the cases where a coordinate is modified in the last minute,
# which coordinate was modified. Since this last-minute change occurs only half of the times, we can make several queries and take as reference values of a and b that appear more than once.
# Once we have the reference a and b, we can start making queries to find the flag. If I make a query and the resulting value of the i-th coordinate of a is different than the reference,
# I can find the value of FLAG[i] by doing (ref_b - b)*(ref_a[i] - a[i])^{-1} mod q. This is because (ref_b - b) = sum_j(ref_a[j]*FLAG[j] - a[j]*FLAG[j]) + e - e = FLAG[i]*(ref_a[i] - a[i]).

# Fun fact: If we already know t of the l characters of the flag, the probability of getting a new character in a query (which is the probability that one of the l-t coordinates that I don't know is
# changed in the last minute in the next query) is 0.5*(l-t)/l. This is because we have a 0.5 probability of modifying a character in the last minute and a (l-t)/l probability of it being a
# new one we don't know. Thus, the expected number of queries to get a new character when knowing t already is 1/(0.5*(l-t)/l) = 2l/(l-t).
# Therefore, the expected number of queries to find the whole flag from scratch is the sum of all these terms with t ranging from 0 to l-1, which is:
# 2l*(1/l + 1/(l-1) + ... + 1/2 + 1/1). In this case l = 28, which gives us an expected number of queries of 219.921... ~ 220 queries.

import socket as sckt
import json
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 13390 

r = remote(HOST, PORT)

def json_recv(socket):
    line = b''
    while True:
        try:
            line += socket.recv(100000)
            return json.loads(line)
        except:
            pass

def json_send(socket, message):
    request = json.dumps(message).encode()
    socket.send(request)


with sckt.socket(sckt.AF_INET, sckt.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(20000), "\n")

    # First, we get the defualt a and b, that we will take as reference.
    ref_a, ref_b = [], -1
    a_candidates, b_candidates = [], []
    T = 8 # Number of samples we take to find the reference a and b
    for t in range(T):
        message = {
            'option': 'get_sample',
        }
        json_send(socket, message)
        response = json_recv(socket)
        a_candidates.append(response['a'])
        b_candidates.append(response['b'])

        message = {
            'option': 'reset',
        }
        json_send(socket, message)
        json_recv(socket)

    for i in range(T):
        if len(ref_a):
            break
        for j in range(i+1,T):
            if a_candidates[i] == a_candidates[j]:
                ref_a, ref_b = a_candidates[i], b_candidates[i]
                print("Found the unchanged a and b!")
                break

    assert(ref_a == [68, 111, 104, 46, 12, 48, 29, 77, 113, 31, 76, 80, 126, 24, 77, 34, 69, 119, 109, 36, 85, 69, 28, 117, 80, 57, 110, 95])
    assert(ref_b == 1)

    # Now, we make queries until we complete the flag by encountering different values at the a's.
    l = len(ref_a)
    characters_found = 0
    flag = [0]*l
    while characters_found < l:
        message = {
            'option': 'reset',
        }
        json_send(socket, message)
        json_recv(socket)

        message = {
            'option': 'get_sample',
        }
        json_send(socket, message)
        response = json_recv(socket)
        a, b = response['a'], response['b']
        if a == ref_a:
            continue

        index = -1
        for i in range(l):
            if a[i] != ref_a[i]:
                index = i 
                break
        if flag[index] != 0:
            continue

        flag[index] = ( (ref_b - b) * pow(ref_a[index] - a[index], -1, q) ) % q
        characters_found += 1
        print(bytes(flag))

    
