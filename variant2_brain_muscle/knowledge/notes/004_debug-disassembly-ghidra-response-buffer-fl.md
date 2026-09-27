---
tags: Debug / disassembly
source: distilled/playbook
---
Ghidra "Response buffer" / "Flow exceeded maximum instructions" errors on C++ linked against heavy header-only template libs (cpp-httplib, boost...): this identifies the binary type, it is not a config error. Read RCX/RDX/R8/R9 right before the CALL, or breakpoint the child function, instead of trying to decompile the parent.
