---
tags: SIMD / vector VM
source: distilled/flareon
---
A VM or check whose opcode handlers are SIMD intrinsics (ymm/xmm registers, vmovdqu/vpmaddubsw/vpshufb) is decoded by mapping each instruction to its intrinsic via the Intel Intrinsics Guide and naming the handler; model the VM state as a register file of N vector regs plus an instruction pointer. Recognize standard algorithms by their input/output size ratios via differential analysis (vary the input, watch which output bytes change): a routine turning 32 bytes into 24 (4->3 grouping) is Base64.
