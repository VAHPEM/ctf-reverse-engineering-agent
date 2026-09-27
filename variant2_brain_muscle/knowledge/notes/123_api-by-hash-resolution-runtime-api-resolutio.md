---
tags: API-by-hash resolution
source: distilled/flareon
---
Runtime API resolution by name-hash (a ROL/XOR family hash such as rol7XorHash32) is de-anonymized with the flare-ida shellcode_hashes IDAPython plugin, which ships precomputed hash tables and annotates nearly all call sites at once. Use capa `-vv` or the capa-explorer plugin to jump to the RWX-alloc / runtime-linking functions first.
