---
tags: In-memory dropper / TTD
source: distilled/flareon
---
Trace a staged in-memory dropper (APC/QueueUserAPC injection into a spawned process like explorer.exe) with Time-Travel Debugging: `tttracer.exe -children target.exe`, then in WinDbg backtrack from allocation/write calls — `dx @$cursession.TTD.Calls("kernel32!VirtualAllocStub")` and WriteProcessMemory — to each stage's RWX buffer, and time-travel to the moment a buffer finishes decrypting to read the plaintext stage.
