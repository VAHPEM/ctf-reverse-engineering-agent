---
tags: Debug embedded shellcode (EB FE)
source: distilled/flareon
---
To catch execution of a base64/registry-stored loader shellcode, patch its first opcode to a self-jump `JMP $-5` (bytes EB FE), launch it (e.g. via QueueUserAPC self-injection from PowerShell), attach a debugger to the spinning thread, then restore the original bytes and step. Set a breakpoint on the loader's final `CALL`/jump-to-entrypoint to reach the loaded PE.
