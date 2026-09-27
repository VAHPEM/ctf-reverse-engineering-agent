---
tags: Tooling / shell gotchas
source: distilled/playbook
---
Hand-rolled AES (not linked to OpenSSL/BCRYPT/CRYPT32): scan for the standard forward/inverse S-box byte signature directly in the file — cheaper than reading strings or blindly decompiling; confirm the algorithm before you know the key/mode.
