---
tags: Crypto
source: distilled/writeup
---
RSA where the public exponent is e = 65537^-1 mod phi(n): then the private exponent d = 65537. Decrypt c directly with the small known exponent — the trick is that the roles of e and d were swapped. Always check whether the given exponent is suspiciously an inverse before assuming you must factor n.
