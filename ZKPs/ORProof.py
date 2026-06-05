### DATA

# Diffie-Hellman group (512 bits)
# p = 2*q + 1 where p,q are both prime, and 2 modulo p generates a group of order q
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

### SOURCE

# from enum import Flag
import random
# from params import p, q, g
import os

# FLAG = os.environ["FLAG"].encode()

# w,y for the relation `g^w = y mod p` we want to prove knowledge of
# w = random.randint(0,q)
# y = pow(g,w,p)
w0 = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y0 = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5
# w1 = REDACTED
y1 = 0x1ccda066cd9d99e0b3569699854db7c5cf8d0e0083c4af57d71bf520ea0386d67c4b8442476df42964e5ed627466db3da532f65a8ce8328ede1dd7b35b82ed617
assert (y0%p) >= 1 and (y1%p) >= 1
assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1


class Challenge:
    def correctness():
        print("Correctness!")
        print(f'Prove to me that you know either w0 or w1, where g^w0 = y0 mod p, g^w1 = y1 mod p')
        # Send first round messages (a0) and (a1), for sigma protocols P1 and P2:
        a0 = int(input("a0:"))
        a1 = int(input("a1:"))

        assert (a0%p) >= 1 and (a1%p) >= 1
        assert pow(a0, q, p) == 1 and pow(a1, q, p) == 1

        # Verifier sends a random challenge sampled from range(0, 2^t) where 2^t <= q
        s = random.randint(0,2**511-1)
        print(f'verifier sends s = {s}')

        # Prover sends (e0,z0) and (e1,z1) such that (a0,e0,z0) and (a1,e1,z1) are satisfying transcripts and e0 xor e1 == s
        e0 = int(input("e0:"))
        e1 = int(input("e1:"))
        z0 = int(input("z0:"))
        z1 = int(input("z1:"))

        # Verifier checks e0 xor e1 == s mod p
        if not e0^e1 == s:
            print("something went wrong with e0^e1 == s")
            exit()
        # Verifier checks g^z0 = A0*h^e0 mod p
        if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:
            print("something went wrong with b=0")
            exit()
            # Verifier checks g^z1 = A1*h^e1 mod p
        if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:
            print("something went wrong with verifying b=1 :(")
            exit()


    def specialSoundness():
        # w,y for the relation `g^w = y mod p` we want to prove knowledge of
        w0 = random.randint(0,q)
        y0 = pow(g,w0,p)
        w1 = random.randint(0,q)
        y1 = pow(g,w1,p)
        assert (y0%p) >= 1 and (y1%p) >= 1
        assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1

        print(f'i will now prove knowledge of w such that either g^w=y0 or g^w=y1 mod p')
        print(f'y0 = {y0}')
        print(f'y1 = {y1}')

        # pick which one we are going to prove knowledge of
        b = random.randint(0,1)
        if b:
            w0,y0,w1,y1 = w1,y1,w0,y0

        # Special soundness!
        print("Special Soundness!")
        # honestly run transcript 0
        r0 = random.randint(0,q)
        a0 = pow(g,r0,p)

        # Simulate transcript 1
        e1 = random.randint(0,2**511-1)
        z1 = random.randint(0,q-1)
        a1 = (pow(pow(y1,e1,p),-1,p) *pow(g,z1,p)) % p

        # randomly sample s
        s = random.randint(0,2**511-1)

        # Complete transcript 0
        e0 = s^e1
        z0 = (r0 + e0*w0) % q

        ### Lets REWIND the prover back to before it received s!
        # We then recompute the e and z values with the new s, and print both transcripts
        # randomly sample s
        s2 = random.randint(0,2**511-1)

        # Complete transcript 0
        e2 = s2^e1
        z2 = (r0 + e2*w0) % q

        # if we swapped w1/w0 now we swap transcripts back
        if b:
            a0,a1,e0,e1,z0,z1 = a1,a0,e1,e0,z1,z0

        print(f'transcript 1:')
        print(f'a0 = {a0}')
        print(f'a1 = {a1}')
        print(f's = {s}')
        print(f'e0 = {e0}')
        print(f'e1 = {e1}')
        print(f'z0 = {z0}')
        print(f'z1 = {z1}')

        # update correct values in second transcript
        if b:
            e1 = e2
            z1 = z2
        else:
            e0 = e2
            z0 = z2

        print(f'transcript 2:')
        print(f'a0 = {a0}')
        print(f'a1 = {a1}')
        print(f's* = {s2}')
        print(f'e0* = {e0}')
        print(f'e1* = {e1}')
        print(f'z0* = {z0}')
        print(f'z1* = {z1}')

        wb = int(input(f'give me a witness!'))

        if not ((wb == w0) or (wb == w1)):
            print("you didn't recover the correct witness :(")
            exit()

        print("Well done! You proved extraction!")

    def SHVZK():
        print(f'Finally, show me you can simulate proofs!')

        # w,y for the relation `g^w = y mod p` we want to prove knowledge of
        w0 = random.randint(0,q)
        y0 = pow(g,w0,p)
        w1 = random.randint(0,q)
        y1 = pow(g,w1,p)
        assert (y0%p) >= 1 and (y1%p) >= 1
        assert pow(y0, q, p) == 1 and pow(y1, q, p) == 1


        s = random.randint(0,2**511-1)
        print(f'y0 = {y0}')
        print(f'y1 = {y1}')
        print(f'give me satisfying transcript for s = {s}')

        a0 = int(input(f'a0: '))
        a1 = int(input(f'a1: '))
        e0 = int(input(f'e0: '))
        e1 = int(input(f'e1: '))
        z0 = int(input(f'z0: '))
        z1 = int(input(f'z1: '))

        # Verifier checks e0 xor e1 == s mod p
        if not e0^e1 == s:
            print("something went wrong with e0^e1 == s")
            exit()
        # Verifier checks g^w0 = A0*h^e0 mod p
        if not pow(g,z0,p) == (a0*pow(y0,e0,p)) % p:
            print("something went wrong with b=0")
            exit()
            # Verifier checks g^z1 = A1*h^e1 mod p
        if not pow(g,z1,p) == (a1*pow(y1,e1,p)) % p:
            print("something went wrong with verifying b=1 :(")
            exit()

    def run():

        ### Correctness!
        # prove to the server you know either w0 or w1
        correctness()

        ### Now do special soundness!!! 
        # The server will compute two satisfying transcripts, extract one of the witnesses :)
        specialSoundness()

        ### SHVZK
        # Finally, show me you can simulate proofs!
        SHVZK()

        print("well done!")
        print(FLAG)

### SOLUTION

import socket
import json

HOST = "archive.cryptohack.org"
PORT = 11840 

# def json_recv(socket):
#     line = b''
#     while True:
#         try:
#             line += socket.recv(100000)
#             return json.loads(line)
#         except:
#             pass
#
# def json_send(socket, message):
#     request = json.dumps(message).encode()
#     socket.send(request + b'\n')

def receive(socket):
    message = socket.recv(10000)
    print(message.decode())
    return message

def send_input(socket, input):
    print(input)
    socket.send(str(input).encode() + b'\n')

# Given an e, a z, and a y, compute the a that makes the transcript valid
def complete_a_for_transcript(tr, y):
    tr[0] = pow(g, tr[2], p) * pow(y, -tr[1], p)
    return tr

def prove_correctness(sckt):
    print("\n\nStart correctness proof.")

    valid_transcript = complete_a_for_transcript(
        [0, random.randint(0,q), random.randint(0,q)],
        y1
    )

    receive(sckt)

    r = random.randint(0,q)
    a0 = pow(g,r,p)

    # params = {
    #     'a0': a0,
    #     'a1': valid_transcript[0],
    # }
    send_input(sckt, a0)
    receive(sckt)
    send_input(sckt, valid_transcript[0])
    response = receive(sckt)
    s = response.decode().split(" ")[4].split("\n")[0]
    s = int(s)

    e0 = valid_transcript[1] ^ s
    z0 = r + e0*w0

    # params = {
    #     'e0': e0,
    #     'e1': valid_transcript[1],
    #     'z0': z0,
    #     'z1': valid_transcript[2],
    # }
    send_input(sckt, e0)
    receive(sckt)
    send_input(sckt, valid_transcript[1])
    receive(sckt)
    send_input(sckt, z0)
    receive(sckt)
    send_input(sckt, valid_transcript[2])
    return


def prove_special_soundness(sckt):
    print("\n\nStart special soundness proof.")
    log = receive(sckt).decode().split('\n')
    transcripts = [{}, {}]
    y0 = log[1].split()[2]
    y1 = log[2].split()[2]
    for i in range(2):
        transcripts[i]['e0'] = int(log[8 + 8*i].split()[2])
        transcripts[i]['e1'] = int(log[9 + 8*i].split()[2])
        transcripts[i]['z0'] = int(log[10 + 8*i].split()[2])
        transcripts[i]['z1'] = int(log[11 + 8*i].split()[2])

    dif0 = transcripts[1]['z0'] - transcripts[0]['z0']
    dif1 = transcripts[1]['z1'] - transcripts[0]['z1']

    if dif0 != 0:
        send_input(sckt, dif0 * pow(transcripts[1]['e0'] - transcripts[0]['e0'], -1, q) % q)
    else:
        send_input(sckt, dif1 * pow(transcripts[1]['e1'] - transcripts[0]['e1'], -1, q) % q)
    return


def prove_SHVZK(sckt):
    print("\n\nStart special honest-verifier zero-knowledge proof.")
    log = receive(sckt).decode().split('\n')
    y0 = int(log[2].split()[2])
    y1 = int(log[3].split()[2])
    s = int(log[4].split()[7])

    # If we were to be completely rigorous, the zeroes should be replaced by random numbers (just as we did in the correctness proof),
    # since this proof assumes an honest verifier that samples the e's randomly. But this way is simpler and doesn't affect the solution 
    # for this particular case. No randomness check is done on the simulator, so this will also pass all the asserts for this challenge.
    tr0 = complete_a_for_transcript([0, 0, 0], y0)
    tr1 = complete_a_for_transcript([0, s, 0], y1)
    tr = [tr0,tr1]

    for i in range(3):
        for j in range(2):
            send_input(sckt, tr[j][i])
            receive(sckt)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    prove_correctness(socket)

    prove_special_soundness(socket)

    prove_SHVZK(socket)

    # challenge = json_recv(socket)
    #
    # e = R
    #
    # params = {
    #         'e': e,
    # }
    # json_send(socket, params)
    #
    # response = json_recv(socket)
    # flag = response['z'] // R
    # print(long_to_bytes(flag))
    #

