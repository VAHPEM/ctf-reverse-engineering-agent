---
tags: Forth
source: distilled/flareon
---
On a Forth challenge, run `words` to list the defined words and inspect the suspicious ones. Recognize threaded-code patterns in the disassembly (`jsr pc,_const` = push a constant; `jsr r4,_docol` = a colon definition). Recover the secret by CHAINING the challenge's own words (e.g. secret/count/decode/decrypt); when the order of two transforms is ambiguous, just try both.
