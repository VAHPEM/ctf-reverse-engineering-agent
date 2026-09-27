---
tags: Control-flow obfuscation / chunking
source: distilled/flareon
---
Shellcode split into tiny 1-2 instruction basic blocks chained by unconditional jmps and scattered through .text amid a benign host-DLL's dead code (JUMPLUMP-style): reassemble it with an IDAPython recursive-descent taint. Walk from EVERY entry point (main + each thread start), follow calls and conditional jumps, record every touched instruction, use `append_func_tail` to attach scattered blocks to their function, and nop out all untainted bytes. Hexrays then decompiles it cleanly.
