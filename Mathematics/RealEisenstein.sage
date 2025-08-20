### SOURCE

import math
from decimal import *
getcontext().prec = int(100)

FLAG = "crypto{???????????????}"
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103]

# h = Decimal(0.0)
#
# for i, c in enumerate(FLAG):
#     h += ord(c) * Decimal(PRIMES[i]).sqrt()
#
# ct = math.floor(h*16**64)
# print(f"ciphertext: {ct}")

# ciphertext: 1350995397927355657956786955603012410260017344805998076702828160316695004588429433


### SOLUTION

assert(len(PRIMES) == 27)

# The operation of printing math.floor(h*16**64) is actually printing the integer part of h and the first 256 bits of its fractional part since 16^64 = 2^256

ct = 1350995397927355657956786955603012410260017344805998076702828160316695004588429433 # ct is 270 bits
assert(ct < 2**270 and ct > 2**269)


# Since we don't actually know the length of the flag, we try with all the possibilities.
for l in range(1,28):
    m = []
    for i, p in enumerate(PRIMES[:l]):
        row = [0 for _ in range(28)]
        row[0] = math.floor(Decimal(int(PRIMES[i])).sqrt() * int(2**256))
        row[i+1] = -1
        m.append(row)

    row = [0 for _ in range(28)]
    row[0] = ct
    m.append(row)
    mat = Matrix(ZZ, m)
    ans = mat.LLL()

    for row in ans:
        isCandidate = True
        for v in row[1:]:
            if v < 0 or v >255:
                isCandidate = False
                break
        if isCandidate:
            flag = ""
            for v in row[1:]:
                flag += chr(v)
            print(l, flag)

