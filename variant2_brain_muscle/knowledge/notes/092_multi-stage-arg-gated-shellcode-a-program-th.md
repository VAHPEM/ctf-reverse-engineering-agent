---
tags: Multi-stage arg-gated shellcode
source: distilled/flareon
---
A program that reads a long delimiter-separated command-line argument and uses each piece to patch or decrypt the next shellcode stage must be solved stage-by-stage: recover each argument piece by satisfying that stage's check (substring compare, length==base-N number, substitution cipher, CRC32, day-of-month arithmetic), then let it decrypt the next stage. Load each extracted blob via IDA File->Load additional binary file and set the segment bitness so it disassembles.
