ords = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

print("".join(chr(o) for o in ords))

cipherBytes = bytes.fromhex("63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d")

print(f"{cipherBytes}")

import base64

cipherBytes = bytes.fromhex("72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf")
base64Encoded = base64.b64encode(cipherBytes)
print(base64Encoded)

from Crypto.Util.number import *

base10 = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
byteString = long_to_bytes(base10)
print(byteString)

#################################################################

message = "label"
key = 13
wordBytes = bytes(message, "utf-8")
newBytes = []
for byte in wordBytes:
	newBytes.append(byte^key)
print(bytes(newBytes))
from pwn import xor
assert(xor(message,key) == bytes(newBytes))


#################################################################

KEY1 = long_to_bytes(0xa6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313)
KEY2xKEY1 = long_to_bytes(0x37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e)
KEY2xKEY3 = long_to_bytes(0xc1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1)
FLAGxKEY1xKEY3xKEY2 = long_to_bytes(0x04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf)

print(xor(FLAGxKEY1xKEY3xKEY2,xor(KEY2xKEY3,KEY1)))

##################################################################

cipher = long_to_bytes(0x73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d)
for i in range(256):
	candidate = xor(cipher,i)
	if candidate[0:6] == bytes("crypto","utf-8"):
		print(f"Byte {i}:", candidate)


##################################################################

cipher = long_to_bytes(0x0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104)
key = ""
for i in range(7):
	key += chr(cipher[i]^ord("crypto{"[i]))
assert(key == "myXORke")
guessKey = bytes("myXORkey", "utf-8")
print(xor(cipher,guessKey))