---
tags: Debug / disassembly
source: distilled/playbook
---
Decompiler heavily polluted by interleaved junk code (a global written/read over and over): fix the decompiler config, patch the microcode, or write a Hex-Rays hook that filters pseudocode by regex — more effective than reading thousands of noisy lines by hand.
