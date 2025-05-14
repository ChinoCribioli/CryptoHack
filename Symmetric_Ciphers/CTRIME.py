# The idea of the solution is that the compress function from zlib recognizes the repetition of patterns and
# and replaces them with smaller tokens to use less space.
# Therefore, if for instance the flag was "hello_world", sending that plaintext to the endpoint will make the function compress the string
# "hello_worldhello_world". Since "hello_world" is indeed a repeated pattern, the resulting compressed string will be shorter than if we were to 
# encrypt some other random plaintext like "johnDoe" and the compression was applied to the string "johnDoehello_world".
# Even better, sending prefixes of the flag will also cause the compression to return shorter outputs. Sending the plaintext "hello_w" will 
# result in a shorter ciphertext than other arbitraty strings of length 7.

# Now, we know that the flag starts with "crypto{" (because it always does), so we run an algorithm that tests every possible next character
# and chooses the one that makes the endpoint return the shortest ciphertext.

# Doing this using "crypto{" as a starting flag, we reach "crypto{CRIM" and after that the endpoint doesn't differentiates any particular character.
# I don't know why this approach fails with this particular character, but based on the name of the challenge my guess was that the next character
# was 'E'. Luckily, after running the algorithm with the starting flag "crypto{CRIME", it finds the rest of the flag correctly :)

import requests

url = 'http://aes.cryptohack.org/ctrime/encrypt/'
flag = "crypto{CRIME"

response = requests.get(url + flag.encode().hex())

target_len = len(response.json()['ciphertext'])

while flag[-1] != '}': 
    print(flag)
    candidate = -1
    target_len = 1000000
    for byte in range(33, 130):
        response = requests.get(url + flag.encode().hex() + f"{byte:02x}")
        if len(response.json()['ciphertext']) <= target_len:
            candidate = byte
            target_len = len(response.json()['ciphertext'])
            print(candidate, flag + chr(candidate), target_len)
    print("candidate: ", candidate, chr(candidate))
    flag += chr(candidate)

print(flag)
