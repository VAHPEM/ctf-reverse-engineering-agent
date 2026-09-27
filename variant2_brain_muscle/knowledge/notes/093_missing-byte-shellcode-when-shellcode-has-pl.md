---
tags: Missing-byte shellcode
source: distilled/flareon
---
When shellcode has placeholder bytes filled in from user input, load it into IDA with a placeholder value (e.g. 0xAA). The incomplete parts disassemble wrong, but the surrounding API-resolution pattern reveals what the missing opcodes must be — that recovers the required input bytes.
