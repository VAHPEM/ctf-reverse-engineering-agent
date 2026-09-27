---
tags: TEA/XTEA weak key
source: distilled/flareon
---
The constant 0x9E3779B9 (or its two's-complement 0x61C88647) with a ~32-round loop marks a TEA/XTEA/XXTEA cipher. Buggy real-world variants use only a 4-byte key (iterating its bytes instead of a full 16-byte key) — a 4-byte keyspace is brute-forceable using a known-plaintext crib (GIF magic GIF89a/GIF87a, a PNG header, etc.) to recognize the correct decryption.
