import requests


def xor(a,b):
    return bytes([b1^b2 for b1,b2 in zip(a,b)])

# First, we note that the ciphertexts are fixed. This is because each plaintext is chosen from a fixed finite set, and the encryption
# is always the same: same key, same counter.
# Since the ciphertexts are fixed, we collect them all.
url = 'http://aes.cryptohack.org/stream_consciousness/encrypt/'
cts = set()
cts = {'45d3c48b6d2b7850b94ce1d6e2f8c090faf65efae3c274775c8c49c9f92e5bd5f0f295106a70839b80e712d96790b108cf7f0ee90bd2abefd44e27588874baf1cdc254', '50c881c27f6e4302b84fe993a3e2d1d9e3f80dfbb0966f3f5f9d49d4ff6b0fcdf4a193596e79999dd48e50df268af90e80', '5dd4d7ce356e7a50bf4cecd1aef597d9c0f91beab0866f711a8c49d6ff240c85f9ee96106d6388dd86be50d533c4b7098d7f09f308d2a1e3994e3f42c972bcf0de9f5446d2cb5ff56b34e87ee5f58aafe875e09f50fbee1ff356f2c394', '589bd2c378226602bc41fed6e2e9de9ce6e80afbf98c673f5c960d9dff240f85f6e495106178809c96a613d769', '45d3d3ce7c6e684da95dadc1b7e2c690faf652b3e08e616654960e9df03f5bcdfef392557a3dcdef91b509d33d8cbf5b', '53ced58b506e7d4bbc42adc0aae3dfd9fcf813bd', '58cf81c878202d56f04ce893b6e3da97b4fe0be7bcc2626a49d800c9b1281acbb1e38410607683d386a21492', '46d3d88b7d212a56b84bf493a5e38896fab10ef2f98c7476539f49dcff2f5bc7e4e88d54607f8a9c95ab1c9c338cbb5ad5360cf940', '46d3c0df392f2a4ebf5aaddca4acdc91fdff19e0b096687e49d81dd5f4255bd6f4e48c556d3199d3d4aa159c348bfe17c02d17f9139ea6e387073245cc26a0f0d8c50e099bd156f22710b23be3e199eaa979e1dc5cfee253fe4ae4c4ddf45a751a9289bb1b5dddbd0a172e34709a2e27445de1e2045989b52d24ffafad74ff8b558cb9d6f8483a536b330c80698ab926c28c60014ad2df94af985011a85fd5', '5eced3943919625bf041f8c1fd', '589bd2c37822660ef067aadfaeacc496e7f45ef6e6877266499000d3f66b12c3b1e984106d7e88cf9ae0049c248bb31f813d00ff14dc', '55c9c4d86a636743bb47e3d4e2edc69db4dc17fffc8b6e7a4f81', '55d4cdc7606e7d4bbc42adc7aae5c692b4e516f2e4c2493850d805d8f03d12cbf6a180107a748ed39aa350d43297bc1bcf3b41fd1196e9e29c46270bdc6eb0ecdcd7151a979f7eb02600ed6fabf39afdec77fd9f51f6a71af904e3c5dfba44611c9f8ffb', '46d3c0df392f2a4cb15df9cae2ffc59cf8fd5ee7f88b733f4d9900d3e56b13c4f5af', '72c9d8db6d217149e357b884b0bf9c94cbe34de6a5d15f2e08a70f89a67f17d8', '41ded3c3783e7902b84baddba3ff8894fde20df6f4c2747758d81dcff0221585f0ef85106062cdde95a41b9c259dfe14ce284fbc2893a7e2d44a3c59cd26bdebd4d8160193cb5eff2554', '50d5c58b506e794ab142e193abebc696e6f45efae4cc', '5fd48d8b5069664ef049e293abe2888dfbb13afcfc8e793f5c960d9de52e17c9b1e98442296299ce95ae17d433c4b10fd5', '589ccc8b6c206243a05ef49fe2c5889df1e21be1e687207649d449c9f92e5bc3f0f48d442e62cdd19da915906786ab0e811646f15f87a7fe955723528867b9f299c5120dd2cc56fd2e59be73eeec9fafe47eaa', '46d4d4c77d6e4302b84ffbd6e2eecd95fdf408f6f4c27477589649c9f92a0f85d8a1825f7c7d899c86a211df2fc4ad0fc23741f81a82bdfe87073c4d886ea0f3d0dd130986d658fe74', '59d4d68b693c6557b40eecdda6acc098e4e107b3f887277351d80bd8b13c13c0ffa18955297688c887e71dc5678ab10ec47e', '45d3c4d87c6e624da25de8c0eeacdc91fde25ef0f19072765c9f0c9dbc6b13cae6a1a810657e8cc89ca250d13e97bb16c77f08f25f86a1ff8707304ada74bcffded45a45d2cb5ff53252ec7eabe183e3a973edcc08b3e506e304de8dc9f2527f1fd186b019148ffc17166b606c976b3e0c55e8e41e17ee'}

# for _ in range(100):
#     response = requests.get(url)
#     cts.add(response.json()['ciphertext'])

# After running 100 requests, we end up with 22 ciphertexts. We can run this a couple of more times to be sure.
# If we run this 300 times, for instance, the probability that there is a 23rd text that we didn't get is (22/23)^300, which
# is negligible. So we can assume that we have all of them.

cts = sorted(cts, key=len)
cts = [bytes.fromhex(ct) for ct in cts]
l = len(cts)

# Now, since we know that the flag starts with 'crypto{', we can find out which of the 22 ciphertexts is the encryption of the flag:
# To test if cts[i] is the correct, we assume it is, get the output of the AES encryption that each plaintext gets xored with by doing
# cts[i]^'crypto{', and reveal all the texts. If most of those texts are coherent english texts, we know that it is the correct.

flag = b'crypto{'

# for i in range(l):
#     print("\n\ncandidate:", i)
#     key = xor(flag, cts[i])
#     for ct in cts:
#         print(xor(ct,key))

ciphertext = cts[4]
encrypted_block = xor(flag,ciphertext)


# After printing the code above, it is clear that the correct ciphertext is ct[4], since all the printed fragments when i = 4 are coherent
# english texts. Next, we will peel each character of the encrypted_block one by one using a frequency analysis: We propose that the i-th character
# of the flag will be c, and c has to (1) be a printable character (between 32 and 126), since it will be a character of the flag, and (2) we will score 
# the resulting character after xoring ct[4][i]^c (which is the proposed i-th character of the block given by the AES encryption) with the i-th character 
# of each ciphertext. Since these characters must be part of an english sentence, it will most likely be an space,
# it will be less likely an 'e', 't', 'a', 'o', or 'i' (the 5 most common letters in the english language), it will less likely be another letter.
# Therefore, if it is a space, we will assign a high grade, if it is one of the 5 most common letter a worse grade, if it is another letter a worse grade,
# if it is another printable character another grade, and we will penalize severly if it is non printable. The character c that has the best grade among
# all the ciphertexts will most likely be the correct one, and that is how we will find our flag.

def is_printable_character(c):
    return 32 <= c <= 126

def grade_character(c):
    if not is_printable_character(c):
        return -100000000
    if c == 32:
        return 30 
    if c in [ord('e'), ord('t'), ord('a'), ord('o'), ord('i')]:
        return 20
    if ord('a') <= c and c <= ord('z'): 
        return 15
    return 0

while len(flag) < len(ciphertext):
    i = len(flag)
    best_score = (-1,-1)
    for c in range(32, 127):
        candidate_block = xor(ciphertext, flag + bytes([c]))
        score = 0
        for ct in cts:
            if len(ct) <= i:
                continue
            score += grade_character(xor(ct,candidate_block)[i])
        if score > best_score[0]:
            best_score = (score, c)
    flag += bytes([best_score[1]])
    encrypted_block += xor(ciphertext, flag)
    print(flag)




