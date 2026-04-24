import numpy as np

M = np.loadtxt('lattice.txt', dtype=int)
print(M.shape)

lat = matrix(M)
reduction = lat.LLL()
np.savetxt('e.txt', reduction, fmt='%d')
print(reduction)
