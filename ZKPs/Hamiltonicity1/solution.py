from hamiltonicity import pedersen_commit, pedersen_open
from hamiltonicity import commit_to_graph, open_graph, permute_graph
from hamiltonicity import hash_committed_graph, testcycle, check_graph
from hamiltonicity import comm_params
import json
import socket

HOST = "archive.cryptohack.org"
PORT = 14635 

numrounds = 128

# Graph with no hamiltonian cycle
# Break the fiat shamir to convince the server this has a cycle to get the flag :)
N = 5
G = [
    [0,0,1,0,0],
    [1,0,0,0,0],
    [0,1,0,0,0],
    [0,0,0,0,1],
    [0,0,0,1,0]
]

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
# This a malleability exploit. Each time I commit to a graph I get a new set of commitments,
# which are random. Therefore, I can generate commitments until the fiat-shamir of the 
# set of commitments gives me the bit I want (I chose 0 in this case).
# Since we know the challenge beforehand, we can forge a malicious proof.

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

