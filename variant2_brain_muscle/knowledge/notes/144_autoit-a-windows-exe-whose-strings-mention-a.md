---
tags: AutoIt
source: distilled/flareon
---
A Windows exe whose strings mention AutoIt is a compiled AutoIt v3 script — decompile it back to source with Exe2Aut (in a VM). Obfuscated AutoIt commonly decrypts each line and executes it, reaching native code via CallWindowProc + DllStructCreate to run embedded shellcode (a decryption stub). Pull the hex shellcode out of the script and analyze that stub separately.
