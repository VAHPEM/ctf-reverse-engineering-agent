---
tags: Office VBA macro
source: distilled/flareon
---
Extract macros from an Office document with oletools `olevba` (or `oledump`). Beware VBA stomping: the compiled p-code can differ from the shown VBA source — dump the p-code (pcodedmp / oletools) to see what actually runs. Macros often deobfuscate a next stage (shellcode, a downloaded payload, a WScript) — follow the decoded string, not the source text.
