---
tags: VM / obfuscation
source: distilled/flareon
---
A switch-case that reads a byte, advances an instruction pointer, and dispatches per value IS a bytecode VM interpreter. Recover the opcode semantics and write a disassembler. Custom VMs are frequently lightly-modified PUBLIC VMs (e.g. PigletVM) — identify the base project and reuse its opcode table/disassembler.
