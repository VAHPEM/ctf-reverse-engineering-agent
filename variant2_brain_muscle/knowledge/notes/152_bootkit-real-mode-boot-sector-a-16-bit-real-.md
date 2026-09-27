---
tags: Bootkit / real-mode boot sector
source: distilled/flareon
---
A 16-bit real-mode boot sector / bootkit is analyzed as 16-bit code (IDA 16-bit, or trace in Bochs/DOSBox/QEMU). Watch for it reserving memory by decrementing the BIOS free-conventional-memory word at 0040:0013 (0x413) and hooking BIOS interrupts (int 13h disk, int 9h keyboard) to hide/patch later stages. Later boot stages are chained from specific disk sectors it reads — extract each sector and disassemble it in order.
