---
tags: Crypto bug as the path
source: distilled/flareon
---
Sometimes the intended solution is a BUG in the challenge's own crypto, not reversing it fully — e.g. a bignum compare that reads little-endian data as big-endian so modexp always returns its input, collapsing ElGamal/RSA. When an operation empirically 'always returns its first argument', model the broken behaviour and solve against THAT (compute M = C2 * S^-1 mod P, etc.) rather than the textbook algorithm.
