---
tags: .NET solving shortcut
source: distilled/flareon
---
For a .NET or mixed-mode crackme you usually don't need the password — add the assembly as a reference in your own C# project and call its method directly with the recovered input, or lift the decryption constants and reproduce it in Python. Watch for a cipher whose state is REUSED across two decrypts (it validates the input string, then WITHOUT re-init decrypts the flag with the same keystream).
