---
tags: Dynamic API resolution by hash
source: distilled/flareon
---
A binary with a blank/empty import table resolves APIs at runtime by NAME HASH passed in a register (often Metasploit's ROR-13 hash). Find the single resolver function, redefine it in IDA with `__usercall` to bind the hash and argument registers, then identify every call site by looking its hash up in a precomputed hash->name table.
