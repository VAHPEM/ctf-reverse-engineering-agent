---
tags: Password check / brute
source: distilled/flareon
---
When a password check splits into INDEPENDENT per-chunk hash comparisons (e.g. 4-byte djb2, a ROT13 hash, Adler32, plus a whole-string FNV1), brute-force each short chunk against its target hash and resolve collisions with the full-string hash. Small chunks crack in under a minute.
