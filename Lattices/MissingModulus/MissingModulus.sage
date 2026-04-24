import numpy as np

M = np.loadtxt('MissingModulus.txt', dtype=int)
print(M.shape)

lat = matrix(M)
reduction = lat.LLL()
print(reduction)
