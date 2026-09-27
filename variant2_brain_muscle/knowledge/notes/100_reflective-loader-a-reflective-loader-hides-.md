---
tags: Reflective loader
source: distilled/flareon
---
A reflective loader hides itself with a stripped DOS header and a modified PE signature (bytes replacing MZ/PE); an egg-hunter that scans memory for a fixed DWORD marker then rolling-XOR-decrypts the bytes after it is the loader's bootstrap. Find the marker to locate the payload.
