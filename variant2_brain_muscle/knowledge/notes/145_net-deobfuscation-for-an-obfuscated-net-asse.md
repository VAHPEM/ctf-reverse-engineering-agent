---
tags: .NET deobfuscation
source: distilled/flareon
---
For an obfuscated .NET assembly, run de4dot first — it auto-detects the obfuscator (SmartAssembly, ConfuserEx, Dotfuscator, Eazfuscator, etc.) and deobfuscates most out of the box (`de4dot file.exe -o out.exe`), restoring readable names/control flow for dnSpy/ILSpy. Only reach for manual/Mono.Cecil work when de4dot fails on a specific protection.
