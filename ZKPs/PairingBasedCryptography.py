### SOURCE

from py_ecc.optimized_bn128 import G1, G2, multiply, pairing
import os

FLAG = b"crypto{?????????????????}"

def gen_test(is_true):
    x = int(os.urandom(8).hex(), 16)
    y = int(os.urandom(8).hex(), 16)
    bias = 1 if is_true else int(os.urandom(2).hex(), 16)
    xG = multiply(G1, x)
    yG = multiply(G2, y)
    zG = pairing(yG, multiply(xG, bias))
    return xG, yG, zG

challenges = []

# for bit in bin(int(FLAG.hex(),16))[2:]:
#     xG, yG, zG = gen_test(int(bit))
#     challenges.append([xG, yG, zG])

# with open("output.txt", "w") as f:
#     for chal in challenges:
#         # Note: in your solution script, you can read each line by calling eval() on it
#         f.write(str(chal))
#         f.write("\n")

### SOLUTION 

from Crypto.Util.number import long_to_bytes
from py_ecc.optimized_bn128 import FQ, FQ2, FQ12
import ast 

with open("data.txt", "r") as f:
    flag_bits = ''
    for _ in range(199):
        xG, yG, zG = ast.literal_eval(f.readline())
        # It seems like xG has is coordinates in F_q but yG has them in F_{q^2}. Also, zG is an element in F_{q^12}.
        xG = [FQ(coord) for coord in xG]
        yG = [FQ2(coord) for coord in yG]
        zG = FQ12(zG)
        if pairing(yG, xG) == zG:
            flag_bits += '1'
        else:
            flag_bits += '0'
        print(flag_bits)
    
    flag = long_to_bytes(int(flag_bits,2))
    print(flag)

