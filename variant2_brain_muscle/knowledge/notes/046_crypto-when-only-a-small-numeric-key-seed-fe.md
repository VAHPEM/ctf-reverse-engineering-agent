---
tags: Crypto
source: distilled/writeup
---
When only a small numeric key/seed feeds the crypto and you already have the expected output (e.g. from a PCAP), brute the full range offline: for each candidate derive the key (MD5→RC4/ChaCha) and compare to the known ciphertext. A few-thousand-wide search is instant and avoids reversing the KDF.
