---
tags: Polyglot / DOS-PE
source: distilled/flareon
---
A PE with no sections, empty data directories, and an AddressOfEntryPoint pointing into an abnormally large DOS stub is a DOS/Windows polyglot: the real DOS logic lives in the stub (run it in DOSBox — use dosbox_with_debugger.exe), and a position-independent Windows payload is embedded too. In IDA load it twice — once with the MS-DOS stub loader as 16-bit, once as the PE.
