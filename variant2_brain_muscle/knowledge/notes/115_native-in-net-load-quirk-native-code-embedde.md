---
tags: Native-in-.NET load quirk
source: distilled/flareon
---
Native code embedded in a .NET assembly that walks the PEB to find kernel32 may only work when the file is loaded AS a .NET assembly (mscoree loads first, fixing kernel32's load-order position). Run raw in x64dbg it resolves the wrong module (kernelbase) and crashes — load it the way it expects, or fix the resolution manually.
