---
tags: Nuitka
source: distilled/flareon
---
A large Windows exe that unpacks itself to `%TEMP%\onefile_%PID%_%TIME%` and relaunches a child, with strings like NUITKA_ONEFILE_PARENT, is Python compiled by Nuitka (onefile mode) — analyze the extracted child, not the launcher. Nuitka stores the program's Python constants (strings, code objects) in the PE RESOURCE section behind a CRC32-checked header as typed blobs (type byte a/u=str, l=int, T=tuple, c/b=bytes); parse the blobs to recover Python-level strings and map them to check functions.
