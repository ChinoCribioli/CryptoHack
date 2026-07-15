from hamiltonicity import pedersen_commit, pedersen_open
from hamiltonicity import commit_to_graph, open_graph, permute_graph
from hamiltonicity import hash_committed_graph, testcycle, check_graph
from hamiltonicity import comm_params
import json
import socket

HOST = "archive.cryptohack.org"
PORT = 14635 

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

#################################### TODO: Rewrite this as a fun fact / mild vulnerability.
# When doing the proof verification, in the case where the challenge bit is 0,
# the verifier never checks that the 'permutation' given in z is indeed a permutation.
# This would let us give a malicious 'permutation' array that makes 
# permute_graph(G, N, permutation) give a different graph that is not equivalent to G.


P = 0x19dad539e2d348cc3ab07d51f2bb6491d1552aa8cf1db928920fd3d86946aed8805d2e279fa8632dd5fbab8aaf7df1069906b057cc785b7f191ef1b9b5da38cff2e7c64da17bb56a058707d9fd69e546a95e502e556a314c587c7ae36c3d1122e6954f5d81dd9239e02f61b045360187b4caeed271cec1919a0d8a39e855040cf
h1 = 250335104192448110684442096964171969189371208477846978499544515755228857598805930673171509152681305793789903169450438090936970626429806187630240086681623358732517929314870247393468568111513100989768455673769015138136779312483203922847547169463972757664497001482465636402329003817055202840451714256443734563502

c0 = 1 + P
c1 = h1
c0_1 = int(str(c0)[:10])
c0_2 = int(str(c0)[10:])
c0c0 = int(str(c0) + str(c0))

# If instead of this original graph
G = [
    [0,0,1,0,0],
    [1,0,0,0,0],
    [0,1,0,0,0],
    [0,0,0,0,1],
    [0,0,0,1,0]
]
# we can flip one edge on the first row and one in the last row, we get a graph with a hamiltonian cycle:
G = [ # Cycle: 0 -> 3 -> 4 -> 2 -> 1 -> 0
    [0,0,0,1,0],
    [1,0,0,0,0],
    [0,1,0,0,0],
    [0,0,0,0,1],
    [0,0,1,0,0]
]
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
# Where c0_1 and c0_2 are two integers such that, when concatenated as strings, give c0.
# And c0c0 means two c0 concatenated as strings.


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
    socket.connect((HOST, PORT))
    state = b''
    permutation = [i for i in range(N)]

    for i in range(numrounds):
        print(f"round {i+1}")
        print(socket.recv(10000).decode())

        comm_graph, openings = commit_to_graph(G,N)
        while hash_committed_graph(comm_graph, state, comm_params)[-1] & 1:
            comm_graph, openings = commit_to_graph(G,N)
        state = hash_committed_graph(comm_graph, state, comm_params)

        message = {
            "A": comm_graph,
            "z": [permutation, openings]
        }

        json_send(socket, message)

    print("finished")
    print(socket.recv(100000).decode())

