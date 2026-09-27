---
tags: Tooling / shell gotchas
source: distilled/playbook
---
Ghidra's console (and analyzeHeadless log) silently DROPS output lines under load, so a script that prints a large result to the console gives you a truncated, misleading view. Have the Ghidra script WRITE its output to a file and read that file back instead of trusting the console dump.
