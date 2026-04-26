import numpy as np

M = np.loadtxt('lattice.txt', dtype=int)
print(M.shape)

lat = matrix(M)
reduction = lat.LLL()
# The e vector will very likely be the first vector of the LLL reduction since it will most likely be the shortest.
e = reduction[0]

# We check it is consistent with the Normal(0,3.8) distribution
for c in e:
    assert(abs(c) < 20)

np.savetxt('e.txt', e, fmt='%d')
print(e)
