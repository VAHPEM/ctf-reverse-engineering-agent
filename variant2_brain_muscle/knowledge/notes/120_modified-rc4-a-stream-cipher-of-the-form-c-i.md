---
tags: Modified RC4
source: distilled/flareon
---
A stream cipher of the form c[i] = p[i] XOR K[i] XOR K[i-1] (K = an RC4 keystream) is still symmetric — re-running it on the ciphertext recovers the plaintext. Watch for Ghidra mis-decompiling the double-XOR (it may collapse num ^ num2 ^ num2 to num incorrectly).
