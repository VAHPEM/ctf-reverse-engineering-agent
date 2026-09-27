---
tags: Rebuild wiped PE headers
source: distilled/flareon
---
A PE dumped from memory usually has its MZ/PE header clobbered. Rebuild it: borrow a full header from a similar binary and fix section offsets by scanning the dump for runs of NULL padding (section alignment) to guess section boundaries; recover the real entry point from DRIVER_OBJECT.DriverInit (kernel) or the crash context. Payloads that resolve APIs dynamically can just be analyzed AS shellcode without a full header rebuild.
