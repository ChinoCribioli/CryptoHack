To understand the solution to this challenge, we have to go through a few points.

First, we have to know that the Data Encryption Standard (DES) belongs to a type of simmetric ciphers called [Feistel Ciphers](https://en.wikipedia.org/wiki/Feistel_cipher#Construction_details). All these algorithms have the same structure: They split the blocks in two parts, Left and Right, and apply several rounds in which $$(L_{i+1}, R_{i+1}) = (R_i, L_i \oplus F(R_i, K_i))$$ where $K_i$ is the key for the ith round and $F$ is a round function. This means that, for decryption, we have the final ciphertext $(L_n, R_n)$ and at each round we calculate $(L_i, R_i)$ as $$(R_{i+1} \oplus F(L_{i+1}, K_i), L_{i+1})$$ until we reach $(L_1,R_1)$, which is the original plaintext.

Note that in both encryption and decryption we have $L_{i+1} = R_i$ and $R_{i+1} = L_i \oplus F(R_i,K_i)$. That is because the set of equations 
\begin{cases} 
    L_{i+1} = R_i \\
    R_{i+1} = L_i \oplus F(R_i, K_i)
\end{cases}
is equivalent to the set
\begin{cases} 
    L_{i} = R_{i+1} \oplus F(L_{i+1}, K_i) \\
    R_{i} = L_{i+1}
\end{cases}
Therefore, the only difference between the encryption and decryption procedure is the order of the subkeys $K_1,K_2,\ldots , K_n$. Even better, we know that, for **any** Feistel cipher, **encrypting** with the key schedule $(K_1,K_2, \ldots, K_n)$ is the same than **decrypting** with the key schedule $(K_n, K_{n-1}, \ldots , K_1)$.

In particular, DES has some known [weak keys](https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES). These are a particular kind of keys that, when feeding them to a DES cipher, you generate a key schedule where all the keys are the same. For instance, the key consisting of all 0 bytes `0x0000000000000000` returns a key schedule where $K_i$ consists of only 0's for every $i$, and the key of all 255 bytes `0xffffffffffffffff` returns a key schedule where all keys consist of only 1's.

Given that DES is a Feistel cipher, if you feed a DES cipher with one of these keys and generate a key schedule of identical keys, you will have an encryption method in which encypting and decrypting are the same. This is, $E(m) = D(m)$ for any message $m$. This condition is equivalent to saying that encrypting twice does nothing, or $E(E(m))=m$ for any $m$.

Now, this challenge uses TripleDES, which uses a key twice the size of a DES key and slice it into two different DES keys. Encryption of TripleDES with key $k_1||k_2$ of the plaintext $m$ is $E_{k_1}(D_{k_2}(E_{k_1}(m)))$ and decryption is $D_{k_1}(E_{k_2}(D_{k_1}(m)))$. Therefore, if we use for the TripleDES key two DES weak keys $k_1$ and $k_2$, we will have the same property for TripleDES: Encrypting and decrypting will be the same. In other words, encrypting twice will do nothing. This is because, if $k_1$ and $k_2$ are DES weak keys, then $E_{k_1} = D_{k_1}$ and $E_{k_2} = D_{k_2}$, and therefore $$E_{k_1}(D_{k_2}(E_{k_1}(m))) = D_{k_1}(E_{k_2}(D_{k_1}(m))).$$

Notice that this property of "encrypting twice does nothing" holds even if we XOR the input and the output with an IV (as long as this IV doesn't change), because applying XOR with an IV twice also does nothing.

Therefore, the solution to this challenge is to first call the `encrypt_flag` method with a key that is the concatenation of two DES weak keys, such as `0x0000000000000000ffffffffffffffff`, and then grab the result of that function and encrypt it again with the same key. The result of that second encryption will be the flag.
