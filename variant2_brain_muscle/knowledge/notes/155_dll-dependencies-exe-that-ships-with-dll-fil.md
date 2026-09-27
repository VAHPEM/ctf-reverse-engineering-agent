---
tags: DLL dependencies
source: distilled/flareon
---
.exe that ships with .dll files: keep them TOGETHER in one directory so the .exe resolves its imports at launch (Windows searches the app dir first) - dynamic analysis fails with 'DLL not found' if the DLLs aren't beside it. But the real logic/flag-check is frequently inside a bundled DLL, not the .exe (which is often just a launcher). Read the .exe's IMPORT table (pe_overview / `rabin2 -i` / objdump -p) to see which DLL and which functions it loads, then reverse THAT DLL's matching exports. For a .NET/MonoGame launcher the code lives in the sibling managed DLL; grep the DLL's strings for the flag first.
