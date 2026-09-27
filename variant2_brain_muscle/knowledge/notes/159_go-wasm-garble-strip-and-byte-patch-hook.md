---
tags: WebAssembly go-wasm
source: distilled/flareon
---
Go js/wasm obfuscated with garble (FLARE-On 13 crux): function/package names are junk, string literals encrypted, and the pclntab magic is CHANGED so tools can't find names. Recover the function table by rebuilding linear memory from the wasm data segments and locating pcHeader by STRUCTURE (`?? ?? ?? ?? 00 00 01 08` + a plausible nfunc) rather than the magic; wasm func idx = n_imports + table index. To trace it, do a MINIMAL byte-patch hook: prepend to the target function body `i32.store [scratch]=id; i32.store [scratch]=PC; global.get 0 (SP); call <a harmless existing import, e.g. runtime.resetMemoryDataView>`, then read the Go args at SP+8 in a JS wrapper; log only on a fresh call (guard on PC). WARNING: a binaryen / wasm-opt roundtrip CORRUPTS a Go wasm module (it hangs after main sets its callback) even with no passes; wasm-decompile segfaults on deeply nested blocks. Hand-write a small stack->expression lifter instead.
