---
tags: .NET / managed
source: distilled/writeup
---
Multi-stage .NET decoders are the norm: an early stage is often a trivial XOR, a later stage RC4. Reproduce each stage in python rather than stepping the debugger; an RC4 key is frequently a base64-looking ASCII string used RAW as the key (not base64-decoded first).
