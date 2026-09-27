---
tags: .NET / managed
source: distilled/writeup
---
In Managed C++ the mangled names (basic_string<char,...>, `\u0020` for space) hide simple logic. Mentally demangle to std::string / space and the method becomes ordinary code. Real operand values live in NATIVE memory, not managed locals, so set a breakpoint at the final compare and read both buffers from the debugger memory window (Ctrl+G to the address).
