p = 1331169830894825846283645180581
a = -35
b = 98
E = EllipticCurve(GF(p), [a,b])
G = E.gens()[0]

n = G.order()
bigFactor = 1153763334005213
cofactor = n // bigFactor
assert(cofactor == 89868478)
assert(p^2 % bigFactor == 1) # Embedding degree = 2

# Based on this: https://gist.github.com/mcieno/f0c6334af28f60d244fa054f5a1c22d2 and https://math.stackexchange.com/questions/4635420/how-can-i-implement-mov-attack-in-sage

F.<u> = GF((p,2)) # F_{p^2}
E = EllipticCurve(F, [a,b]) # The same curve but extended over the extended base field
#print(E.order().factor())
#print(P.order().factor())

A = E(1110072782478160369250829345256, 800079550745409318906383650948, 1)
G = E(479691812266187139164535778017, 568535594075310466177352868412, 1)

assert(29618469991922269*G == A)

P = E.gens()[0]
wA = P.weil_pairing(A,P.order())
wG = P.weil_pairing(G,P.order())

m = 29618469991922269
# m = wA.log(wG)
print(m)
assert(m*G == A)


