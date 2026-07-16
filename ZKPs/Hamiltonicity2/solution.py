from hamiltonicity import pedersen_commit, pedersen_open
from hamiltonicity import commit_to_graph, open_graph, permute_graph
from hamiltonicity import hash_committed_graph, testcycle, check_graph
from hamiltonicity import comm_params
import json
import socket

HOST = "archive.cryptohack.org"
PORT = 34597 

numrounds = 128

def json_recv(socket):
    line = b''
    while True:
        try:
            line += socket.recv(100000)
            return json.loads(line)
        except:
            pass

def json_send(socket, message):
    request = json.dumps(message).encode()
    socket.send(request + b'\n')

### SOLUTION:

# When doing the FS transformation to get the challenges, the verifier erases the separators of the 
# matrix of commitments when doing
# `first_message = "".join([str(x) for xs in G for x in xs])`.
# This implies that, for instance, A = [[1,2],[3,45]] will give the same FS state as 
# A = [[1,2],[34,5]], or A = [[12,3],[4,5]].
# This gives us room for malleability and will let us craft two commitment matrices comm_0 and comm_1 
# such that they are indistinguishable to the FS state but they let us forge a valid proof for each
# challenge.

P = 0x19dad539e2d348cc3ab07d51f2bb6491d1552aa8cf1db928920fd3d86946aed8805d2e279fa8632dd5fbab8aaf7df1069906b057cc785b7f191ef1b9b5da38cff2e7c64da17bb56a058707d9fd69e546a95e502e556a314c587c7ae36c3d1122e6954f5d81dd9239e02f61b045360187b4caeed271cec1919a0d8a39e855040cf
h1 = 250335104192448110684442096964171969189371208477846978499544515755228857598805930673171509152681305793789903169450438090936970626429806187630240086681623358732517929314870247393468568111513100989768455673769015138136779312483203922847547169463972757664497001482465636402329003817055202840451714256443734563502

# The commitments for 0 and 1 will be 1 and h1 respectively, so that r is always 0. That way is easier to implement.
# We want c0 to be equivalent to 1 mod P but with more than 1 character so that we can split it in parts.
# Luckily, the verifier never checks that the integers in A are in range. In case it did, we could simply commit with another value of r to get a non-trivial commitment of 0.
c0 = 1 + P 
c1 = h1

# If instead of this original graph
G = [
    [0,0,1,0,0],
    [1,0,0,0,0],
    [0,1,0,0,0],
    [0,0,0,0,1],
    [0,0,0,1,0]
]
# we flip one edge on the first row and one in the last row, we get a graph with a hamiltonian cycle:
G = [ # Cycle: 0 -> 3 -> 4 -> 2 -> 1 -> 0
    [0,0,0,1,0],
    [1,0,0,0,0],
    [0,1,0,0,0],
    [0,0,0,0,1],
    [0,0,1,0,0]
]

# In order to flip edges while maintaining the FS state, we shrink some commitments and enlarge others.
# Concretely, we split one commitment into two parts for it to occupy two places of the matrix, and 
# merge two other commitments for them to occupy only one place of the matrix.
# That way, we can turn a commitment of [0,0,1,0,0] into a commitment of [_,_,_,1,_].
# This can be done by transforming [c0,c0,c1,c0,c0] into [c0,c0_1,c0_2,c1,c0c0],
# where c0_1 and c0_2 are two integers such that, when concatenated as strings, give c0
# and c0c0 means two c0 concatenated as strings.
# This turns a commitment of the row [0,0,1,0,0] into a commitment such that the fourth coordinate
# is a commitment of 1 (remember that, for the case of challenge = 1, we don't need to reveal the whole
# graph, only the edges that we are using in our cycle). We do the same in the last row.
c0_1 = int(str(c0)[:10])
c0_2 = int(str(c0)[10:])
c0c0 = int(str(c0) + str(c0))

# For the case where challenge is 0, I send an honest commitment of the original graph:
comm_0 = [
    [c0,c0,c1,c0,c0],
    [c1,c0,c0,c0,c0],
    [c0,c1,c0,c0,c0],
    [c0,c0,c0,c0,c1],
    [c0,c0,c0,c1,c0]
]
# And for the case where challenge is 1, I send a commitment of the edges of the flipped graph,
# making sure that the concatenation of the commitments of all the edges is the same as the other case:
comm_1 = [
    [c0,c0_1,c0_2,c1,c0c0],
    [c1,c0,c0,c0,c0],
    [c0,c1,c0,c0,c0],
    [c0,c0,c0,c0,c1],
    [c0,c0c0,c1,c0_1,c0_2]
]

# We prepare a response for each of these cases:
# z_0 will have a trivial permutation and the regular openings.
z_0 = ([0,1,2,3,4], [
    [(0,0) if edge == c0 else (1,0) for edge in row] for row in comm_0
])
# z_1 will have the cycle and the openings.
z_1 = ([(0,3), (3,4), (4,2), (2,1), (1,0)], [0,0,0,0,0])


FS_state = b''
assert(hash_committed_graph(comm_0, b'random', comm_params) == hash_committed_graph(comm_1, b'random', comm_params))

for _ in range(128):
    FS_state = hash_committed_graph(comm_0, FS_state, comm_params)
challenge_bits = bin(int.from_bytes(FS_state, 'big'))[-128:]
challenges = [int(c) for c in challenge_bits]


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))

    for i in range(numrounds):
        print(f"round {i+1}")
        print(socket.recv(10000).decode())

        if challenges[i]:
            message = {
                "A": comm_1,
                "z": z_1
            }
        else:
            message = {
                "A": comm_0,
                "z": z_0
            }

        json_send(socket, message)

    print("-----------------Finished-----------------")
    print(socket.recv(100000).decode())


# FUNFACT:
# When doing the proof verification, in the case where the challenge bit is 0,
# the verifier never checks that the 'permutation' given in z is indeed a permutation.
# This would let us give a malicious 'permutation' array that makes 
# permute_graph(G, N, permutation) give a different graph that is not equivalent to G.
# Particularly, the 'permutation' array can have repeated values, which will translate in 
# a G where two different nodes are an exact copy of each other in terms of edges.
# I couldn't find an exploit to this vulnerability because there is no such graph that 
# we can get from 'permute_graph(G, N, permutation)' that contains a hamiltonian cycle.
