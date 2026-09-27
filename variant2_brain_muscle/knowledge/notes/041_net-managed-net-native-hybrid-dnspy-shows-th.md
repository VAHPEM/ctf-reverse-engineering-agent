---
tags: .NET / managed
source: distilled/writeup
---
.NET + native hybrid: dnSpy shows the managed half, Ghidra the native half — neither alone is complete. The string/flag decryption typically happens in the native DLL (decode a phrase, then the flag); follow both views together and let the managed side tell you which native export does the work.
