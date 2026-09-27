---
tags: Feistel decryption
source: distilled/flareon
---
Recognize a Feistel cipher (split block into halves, run one half through a round function and XOR into the other, swap halves each round). You can DECRYPT with the exact same code by only reversing the round-key order — no need to invert the round function. If the key schedule is obfuscated, dump it from the running program (infinite-loop patch) and reverse the key list.
