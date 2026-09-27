---
tags: VM / obfuscation
source: distilled/writeup
---
A repeated `lea reg,[next]; push reg; ret` pattern is not normal control flow — it is chunked control-flow flattening / a hand-rolled VM dispatch. Follow the chunk chain to reconstruct the VM's state layout (which stack/array slots are the accumulators) and per-opcode semantics; conditional chunks branch mid-chunk before the tail dispatch.
