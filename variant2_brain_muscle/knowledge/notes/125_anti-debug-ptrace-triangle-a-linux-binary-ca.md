---
tags: Anti-debug ptrace triangle
source: distilled/flareon
---
A Linux binary can defend itself with mutually-ptracing processes (parent + a child debugger + a watchdog debugging the child); the real logic is split across all three and syscalls are intercepted with PTRACE_SYSEMU and emulated as an RPC mechanism, so a normal debugger can't attach and single-process reasoning fails. To read a decrypted buffer, patch an infinite loop into the parent right after the decrypt and dump /proc/<pid>/mem (these usually have no anti-patching), or SIGKILL the child then attach.
