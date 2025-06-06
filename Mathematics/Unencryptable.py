###  SOURCE

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

DATA = bytes.fromhex("372f0e88f6f7189da7c06ed49e87e0664b988ecbee583586dfd1c6af99bf20345ae7442012c6807b3493d8936f5b48e553f614754deb3da6230fa1e16a8d5953a94c886699fc2bf409556264d5dced76a1780a90fd22f3701fdbcb183ddab4046affdc4dc6379090f79f4cd50673b24d0b08458cdbe509d60a4ad88a7b4e2921")
FLAG = b'crypto{??????????????????????????????????????}'

def gen_keypair():
    p = getPrime(512)
    q = getPrime(512)
    N = p*q
    e = 65537
    phi = (p-1)*(q-1)
    d = inverse(e,phi)
    return N,e,d


def encrypt(m,e,N):
    m_int = bytes_to_long(m)
    c_int = pow(m_int,e,N)
    if m_int == c_int:
        print('RSA broken!?')
        return None
    else:
        return c_int

N,e,d = gen_keypair()
N = 89820998365358013473897522178239129504456795742012047145284663770709932773990122507570315308220128739656230032209252739482850153821841585443253284474483254217510876146854423759901130591536438014306597399390867386257374956301247066160070998068007088716177575177441106230294270738703222381930945708365089958721

# encrypted_data = encrypt(DATA,e,N)
# encrypted_flag = encrypt(FLAG,e,N)

# print(f'N = {hex(N)}')
# print(f'e = {hex(e)}')
# print(f'c = {hex(encrypted_flag)}')

### DATA 

# Unblvr: ~ % python3 source.py
# RSA broken!?
N = 0x7fe8cafec59886e9318830f33747cafd200588406e7c42741859e15994ab62410438991ab5d9fc94f386219e3c27d6ffc73754f791e7b2c565611f8fe5054dd132b8c4f3eadcf1180cd8f2a3cc756b06996f2d5b67c390adcba9d444697b13d12b2badfc3c7d5459df16a047ca25f4d18570cd6fa727aed46394576cfdb56b41
e = 0x10001
c = 0x5233da71cc1dc1c5f21039f51eb51c80657e1af217d563aa25a8104a4e84a42379040ecdfdd5afa191156ccb40b6f188f4ad96c58922428c4c0bc17fd5384456853e139afde40c3f95988879629297f48d0efa6b335716a4c24bfee36f714d34a4e810a9689e93a0af8502528844ae578100b0188a2790518c695c095c9d677b

### SOLUTION

data_int = bytes_to_long(DATA)
assert(data_int == pow(data_int,e,N))
assert(pow(data_int,0x10000,N) == 1)
assert(encrypt(b'fgasdt52345',e,N) != None) # Not every number breaks this RSA

# Since encypt(DATA) equals DATA, we know that decrypt(DATA) must also be equal to DATA. Therefore d must meet that DATA^d = DATA mod N.
# This tells us that, both e and d belong to the set {k*ord + 1}, where ord is the order of the integer DATA modulo N.
# Therefore, ord | e-1. Since e-1 = 0x10000 = 2^16, we know that ord = 2^r for r <= 16. Turns out that r is 9.
# So, we know that d = 1 mod 2^9.

# The fact that DATA^{2**9} = 1 mod N tells us that N | DATA^{2**9} - 1. Therefore p and q both divide that expression.
# Now, we can factor the expression to (DATA^{2**8} - 1)(DATA^{2**8} + 1). The former can be further factorized as 
# (DATA^{2**7}-1)(DATA^{2**7}+1)(DATA^{2**8}+1). And we can keep on with the first expression until we get that N divides
# (DATA - 1)(DATA + 1)(DATA^{2} + 1)(DATA^{2**2} + 1)(DATA^{2**3} + 1)...(DATA^{2**8} + 1).
# So, if the factors of N (p and q) are in different factors of the expression, we can find them by calculating the gcd between N and each separate factor.

def gcd(a,b):
    if a>b:
        return gcd(b,a)
    if a == 0:
        return b
    return gcd(b%a,a)

print("-1",gcd(data_int-1,N))
for i in range(9):
    print(i, gcd(pow(data_int,2**i,N)+1,N))

# This gives us
p = 10900824353334471830007307529937357926160386461967884446160315218630687793341471079170750548554707926611542019859296605188535413447791710067186432371970369
q = 8239835397208516111720362847949425401045672365829937602117480449316694558226622200110057535873802132963548914201468383545676262090246827792522994758916609
assert(p*q == N)

phi = (p-1)*(q-1)
d = pow(e,-1,phi)
flag = pow(c,d,N)
print(long_to_bytes(flag))

