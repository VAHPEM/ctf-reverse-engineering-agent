---
tags: Cipher reversal
source: distilled/flareon
---
A custom serial check built from a stream cipher's keystream (salsa20/chacha) plus an N-round Feistel/XOR network is reversed by regenerating the same keystream and inverting the round loop (reverse the iteration order and swap the two halves each round). Base64 input is recognizable by its lookup table in the code.
