---
tags: WebAssembly
source: distilled/flareon
---
A browser challenge shipping a `.wasm` module: convert it to text with wabt's `wasm2wat` to read the WAT, and use the accompanying JavaScript to see how the module's exports are called and what memory/imports it gets. Reason about the WAT logic directly (tooling is limited); a decompiler like the wasm plugins or hand-tracing the stack machine recovers the check.
