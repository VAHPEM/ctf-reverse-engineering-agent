---
tags: embedded-runtime dynamic-first
source: distilled/flareon
---
Inside an embedded engine you usually don't need to reverse the obfuscated bytecode statically - you can REPLACE the script/input at the load boundary and measure the native functions as black boxes. Break where the host hands the script/string to the engine (e.g. the V8 String::NewFromUtf8 wrapper, or the WASM instantiate/import edge), overwrite that buffer with your own probe code (adjust the length register), and let the engine run it. FLARE-On 13 neon_outrun (Tauri/Rust/V8): the Rust side had OVERRIDDEN built-ins (Array.sort, Math.min, String.replaceAll) with native functions - looked normal in the game's JS. Swapping the game script for a probe and feeding chosen values recovered each native's behaviour (a per-lap cos weight = required lap time = a flag byte) without gutting the control-flow-flattened native code. Generalises to Lua/Python engines too.
