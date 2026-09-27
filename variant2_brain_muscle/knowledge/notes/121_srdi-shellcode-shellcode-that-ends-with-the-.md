---
tags: sRDI shellcode
source: distilled/flareon
---
Shellcode that ends with the ASCII marker `dave` (the tool's default trailer) is a DLL converted to position-independent shellcode by sRDI; it reflectively loads an embedded PE and calls one of its exports. The loader computes the embedded PE's start via a call/pop + fixed offset — carve that PE out and analyze it instead of the loader.
