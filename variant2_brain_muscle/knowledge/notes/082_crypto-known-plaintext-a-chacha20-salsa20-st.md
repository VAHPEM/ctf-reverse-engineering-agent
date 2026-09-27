---
tags: Crypto / known-plaintext
source: distilled/flareon
---
A ChaCha20/Salsa20 state always contains the ASCII constant `expand 32-byte k`. Its known bytes are a reliable crib: use them to locate the key/state in memory and as known-plaintext for RSA-key-recovery attacks on an encrypted state matrix.
