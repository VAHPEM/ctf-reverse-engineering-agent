---
tags: Python / bytecode
source: distilled/playbook
---
A challenge with N copies of the same check function (randomized template + per-copy constants): do not read each copy — confirm the finite template set on a few samples, then write an automatic recognizer (regex on the disassembly, or symbolic execution via angr) applied to all of them.
