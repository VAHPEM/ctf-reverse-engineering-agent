---
tags: Native / encryptor
source: distilled/writeup
---
An encryptor/ransomware EXE: do NOT run it. Find the FindFirstFile/FindNextFile loop, isolate the per-file transform it calls, and write the INVERSE to decrypt the provided samples. The key/IV is usually derived from a fixed constant or the filename, visible statically.
