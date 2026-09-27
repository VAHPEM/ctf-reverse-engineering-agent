---
tags: TTD scripting for VM trace
source: distilled/flareon
---
To understand a VM, script a per-opcode trace in WinDbg Time-Travel Debugging (JavaScript debugger model): breakpoint the dispatch, read the opcode and operand bytes at the VM program counter, and log one human-readable line per virtual instruction. `@$cursession.TTD.Calls("mod+off").Count()` counts how often a given handler ran. This converts an opaque VM into a readable instruction log you can replay backward and forward.
