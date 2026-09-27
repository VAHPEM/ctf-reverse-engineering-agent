---
tags: Decrypt many per-key strings by emulation
source: distilled/flareon
---
When each string is decrypted by an RC4/XOR routine with a DIFFERENT per-call key (so FLOSS's static scan can't recover them), script flare-emu to iterate the cross-references to that routine, emulate each call with its actual arguments, and annotate the decrypted result. Works for both user-mode and kernel-mode (driver) binaries.
