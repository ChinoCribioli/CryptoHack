### SOURCE

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from os import urandom
# from utils import listener

FLAG = "crypto{???????????????????????????????}"


class CFB8:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        IV = urandom(16)
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = b''
        state = IV
        for i in range(len(plaintext)):
            b = cipher.encrypt(state)[0]
            c = b ^ plaintext[i]
            ct += bytes([c])
            state = state[1:] + bytes([c])
        return IV + ct

    def decrypt(self, ciphertext):
        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = IV
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0]
            c = b ^ ct[i]
            pt += bytes([c])
            state = state[1:] + bytes([ct[i]])
        return pt


class Challenge():
    def __init__(self):
        self.before_input = "Please authenticate to this Domain Controller to proceed\n"
        self.password = urandom(20)
        self.password_length = len(self.password)
        self.cipher = CFB8(urandom(16))

    def challenge(self, your_input):
        if your_input['option'] == 'authenticate':
            if 'password' not in your_input:
                return {'msg': 'No password provided.'}
            your_password = your_input['password']
            if your_password.encode() == self.password:
                self.exit = True
                return {'msg': 'Welcome admin, flag: ' + FLAG}
            else:
                return {'msg': 'Wrong password.'}

        if your_input['option'] == 'reset_connection':
            self.cipher = CFB8(urandom(16))
            return {'msg': 'Connection has been reset.'}

        if your_input['option'] == 'reset_password':
            if 'token' not in your_input:
                return {'msg': 'No token provided.'}
            token_ct = bytes.fromhex(your_input['token'])
            if len(token_ct) < 28: 
                return {'msg': 'New password should be at least 8-characters long.'}

            token = self.cipher.decrypt(token_ct)
            new_password = token[:-4]
            self.password_length = bytes_to_long(token[-4:])
            self.password = new_password[:self.password_length]
            return {'msg': 'Password has been correctly reset.'}


# import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
# listener.start_server(port=13399)

### SOLUTION

# The token_ct should have 28 bytes because the first 16 will be the IV (intial state when decrypting), and the final 4 will be the password_length, so there should be at least 8 bytes remaining.

# Discarded ideas:

# Idea: At the end of the 'reset_password', the self.password is set to new_password[:password_length],
# where password_length is the last 4 bytes of the decrypted token. However, it is never checked that the length is the actual length of the 
# new_password, it is just a number obtained from 4 "randomly decrypted" bytes. So my guess is that we can somehow force the last four bytes
# to be 0, so the password would end up being "". Note that x[:l] is x if l > len(x).

# If I could know password_length I could solve the challenge: I propose a token (a1,a2) where a2 are the last 4 bytes. This will decode to something
# where the last four bytes are x. Therefore, I change the password and propose token (a1,a2^x), which will decode to exactly the same password 
# as before except for the last 4 bytes. The first of these 4 bytes will be 0, because the state will be the same as with a1, so the byte 'b' to xor 
# with that character will be the same as with a2[0], so the resulting decoded byte will be a2[0]^x[0]^b. But we know that a2[0]^b is x[0], so we will
# get the 0 byte. Therefore, if we send (a1,a2^x) as a token, the resulting password will have a 0 in the first of the last four bytes.
# Applying the same logic again, getting the new password length y and proposing (a1,a2^x^y) as a token, we will get a 0 as the second byte, and so on.


# Solution:
# Important note regarding the decryption scheme: Given a ciphertext ct, the decryption of character i only depends on ct[(i-16):i].
# If you send a token that consists of always the same character, then the state of the decryption will stay always the same because the update is
# state = state[1:] + bytes([ct[i]])
# Therefore, the 'b' that we obtain from the AES cipher that we use to xor with the ct to get the pt will always be the same. This, given that the ct is just 
# a repeating character, will result in a pt also consisting on a repeating character. Therefore, there are only 256 posibilities for the password.
# Let's implement an example of this:
cipher = CFB8(urandom(16))
print(cipher.decrypt(b'1'*28))
# This code should return a 16-bytes string consisting of a repeating byte.

import socket
import json

HOST = "socket.cryptohack.org"
PORT = 13399 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    
    print(socket.recv(10000), "\n")
    reset_password = {
        'option': 'reset_password',
        'token': (b'j'*28).hex()
    }
    print(reset_password)
    socket.send(json.dumps(reset_password).encode('utf-8'))

    print(socket.recv(10000), "\n")


    for b in range(256):
        challenge = {
            'option': 'authenticate',
            'password': (long_to_bytes(b)*8).decode('utf-8')
        }
        socket.send(json.dumps(challenge).encode('utf-8'))
        
        response = socket.recv(1000)
        if response != b'{"msg": "Wrong password."}\n':
            print(response)
            break
