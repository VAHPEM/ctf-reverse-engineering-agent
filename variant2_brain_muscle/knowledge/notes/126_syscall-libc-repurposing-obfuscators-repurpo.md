---
tags: Syscall / libc repurposing
source: distilled/flareon
---
Obfuscators repurpose innocuous libc calls as hidden operations: glibc `nice()` actually invokes getpriority/setpriority, whose tracer handlers do string decryption; chmod/truncate/uname handlers can implement a cipher's round function. Trace what each syscall's HANDLER does in the tracer, not what the libc name suggests, and watch for decoy string tables that are decoded but never used (pure time-wasters).
