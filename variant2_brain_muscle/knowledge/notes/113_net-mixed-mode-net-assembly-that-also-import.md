---
tags: .NET mixed-mode
source: distilled/flareon
---
.NET assembly that ALSO imports kernel32.dll (beyond mscoree.dll) is mixed-mode: its real logic is native and hidden from dnSpy. Confirm via the COR20 header (IL-only flag clear; sometimes Native EntryPoint set). To analyze the native half in IDA, switch the loader from 'Microsoft .NET assembly' to plain 'Portable executable (PE)', take the entry from the COR20 EntryPointToken RVA, and mark the un-referenced code there as a function.
