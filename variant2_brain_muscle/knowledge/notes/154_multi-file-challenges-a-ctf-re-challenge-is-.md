---
tags: Multi-file challenges
source: distilled/flareon
---
A CTF/RE challenge is usually a BUNDLE of files, not one binary: a binary plus a pcap, a memory/crash dump, a disk or firmware image, encrypted sample files, a README/hint. Survey ALL inputs first (get each file's type), then reason about how they RELATE - a binary explains the pcap or dump it produced; a decryptor pairs with the encrypted samples; firmware pairs with a disk image; a README or a known file format gives the crib/known-plaintext. The flag often lives in the file you did NOT open first.
