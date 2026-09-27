---
tags: Crypto / identify by string
source: distilled/flareon
---
A crypto library's own error/format strings name the primitive: e.g. `chacha20poly1305: bad key length` => (X)ChaCha20-Poly1305, and a 32-byte key with a 24-byte nonce => the XChaCha20 variant. Let the library strings tell you the algorithm and its parameter sizes.
