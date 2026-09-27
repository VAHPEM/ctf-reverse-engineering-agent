---
tags: Machine-SID-seeded names
source: distilled/flareon
---
When a sample derives its registry key/value names or filenames pseudo-randomly from a wordlist seeded by the host machine SID, the names won't match on your box. Recover the original SID by grepping the provided hive for `S-1-5-21-` (strip the trailing RID), then patch the machine-ID function to that value or reproduce the PRNG (xorshift64*/128*) in Python to regenerate the names.
