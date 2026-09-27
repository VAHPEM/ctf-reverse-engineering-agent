---
tags: Crypto / recognize by constant
source: distilled/flareon
---
RC5/RC6 are identified by the magic constants P=0xB7E15163 and Q=0x9E3779B9 with a ~20 (0x14) round count; 0x9E3779B9 (golden ratio) alone also appears in TEA/XTEA. CRC32 uses polynomial 0xEDB88320. Grep for these to name the primitive without reversing the schedule.
