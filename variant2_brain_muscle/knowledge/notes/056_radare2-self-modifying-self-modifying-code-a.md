---
tags: radare2 / self-modifying
source: distilled/writeup
---
Self-modifying code (a loop that xor/add/sub-patches a code region in memory before jumping into it): apply the transform STATICALLY in radare2 with write-with-operation over the block — `wox <hex>` (xor), `woa` (add), `wos` (sub) `@ addr!len` — then re-disassemble the now-plaintext bytes. You read the real code without ever executing the sample.
