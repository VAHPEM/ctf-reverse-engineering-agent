---
tags: No-FLIRT / unusual compiler
source: distilled/flareon
---
When IDA lacks FLIRT signatures for the compiler (OpenWatcom 16-bit DOS, Tiny C, exotic toolchains), library and main() aren't auto-identified — find the entry/main manually by following the C-runtime startup to the call that takes argc/argv, and label runtime helpers yourself. Identify the compiler from the DOS stub / rich header / runtime strings to know what conventions to expect.
