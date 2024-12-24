import numpy as np 

v = np.array([
    [4,1,3,-1],
    [2,1,-3,4],
    [1,0,-2,7],
    [6,2,9,-5]
])

def Gram_Schmidt(v):
    u = np.zeros(v.shape)
    mu = np.zeros(v.shape)
    for i in range(v.shape[0]):
        u[i] = v[i]
        for j in range(i):
            mu[i][j] = v[i].dot(u[j])/np.inner(u[j],u[j])
        for j in range(i):
            u[i] -= mu[i][j]*u[j]
        # u[i] /= np.linalg.norm(u[i])
    return u

u = Gram_Schmidt(v)
for i in range(u.shape[0]):
    for j in range(0,i):
        assert(u[i].dot(u[j])**2 < 0.000000001)

print(u)

v = np.array([
    [6,2,-3],
    [5,1,4],
    [2,7,1],
])

print(np.linalg.det(v))
