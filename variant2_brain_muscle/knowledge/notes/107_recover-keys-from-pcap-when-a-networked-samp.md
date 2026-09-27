---
tags: Recover keys from PCAP
source: distilled/flareon
---
When a networked sample negotiates a symmetric key/nonce over TCP with visible ACK markers (e.g. ACK_K / ACK_N), find those strings in the provided PCAP, follow the TCP stream, and read the 32-byte key and nonce straight from the bytes — then decrypt offline with the matching library (HC-256 via RustCrypto, ChaCha, etc.).
