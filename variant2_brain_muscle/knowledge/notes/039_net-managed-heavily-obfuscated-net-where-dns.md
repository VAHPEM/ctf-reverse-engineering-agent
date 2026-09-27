---
tags: .NET / managed
source: distilled/writeup
---
Heavily obfuscated .NET where dnSpy refuses to decompile some methods: deobfuscate using the binary's OWN code via Mono.Cecil — load the assembly, invoke/emulate its decoder methods, and dump the generated (e.g. `Flared_XX`) method bodies. The unpacker you need is usually already inside the sample.
