---
tags: Self-patching key handoff
source: distilled/flareon
---
When one stage generates a key and PATCHES it into the binary for a later stage to read, find the marker it scans for — e.g. a 16-byte 0xCC run followed by a `CALL; POP EAX; RET` stub — that fixed tag locates where the key is written and later read.
