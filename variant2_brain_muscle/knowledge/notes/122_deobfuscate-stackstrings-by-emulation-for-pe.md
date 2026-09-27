---
tags: Deobfuscate stackstrings by emulation
source: distilled/flareon
---
For per-string stackstring XOR obfuscation (a string built byte-by-byte on the stack then XOR-decoded just before use), emulate each decode sequence with flare-emu (IDA + Unicorn): run from the sequence start to just past the XOR-loop `jb`, then read the decoded string from emulated memory and set it as a comment. FLOSS (with `-s` for shellcode) also extracts stackstrings automatically.
