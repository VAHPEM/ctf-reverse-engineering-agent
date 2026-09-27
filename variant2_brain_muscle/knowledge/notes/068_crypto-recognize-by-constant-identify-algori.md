---
tags: Crypto / recognize by constant
source: distilled/flareon
---
Identify algorithms by their magic constants instead of reversing the loop: FNV1 uses prime 0x1000193 + offset basis 0x811c9dc5; the MSVC `rand` LCG uses multiplier 0x343fd, increment 0x269ec3, modulus 0x80000000. Grep the binary for these.
