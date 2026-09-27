---
tags: YARA-as-challenge
source: distilled/flareon
---
When the challenge IS a YARA rule, reconstruct the file it matches: split the AND-joined condition one expression per line and sort. Most expressions are redundant (always-true bitwise/range/`!=` checks); only the equality (`==`) ones constrain bytes. Solve the arithmetic ones (add/sub/xor, minding `uint` endianness) and brute-force 2-byte fragments from their CRC32/MD5/SHA256 (rainbow tables help).
