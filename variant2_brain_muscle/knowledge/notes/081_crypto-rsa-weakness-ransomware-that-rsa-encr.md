---
tags: Crypto / RSA weakness
source: distilled/flareon
---
Ransomware that RSA-encrypts its symmetric key with a SMALL exponent (e=3) and no padding is breakable. If m^e is only slightly larger than N, recover m by finding k in m^e = c + k*N — filter candidate k so the low bytes of (c + k*N) match the KNOWN low bytes of the plaintext (e.g. the fixed ChaCha constant), then take the e-th (cube) root. If a small part of the plaintext is unknown, finish with Coppersmith's attack.
