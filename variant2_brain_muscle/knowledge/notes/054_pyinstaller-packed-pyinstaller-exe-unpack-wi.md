---
tags: PyInstaller / packed
source: distilled/writeup
---
PyInstaller EXE: unpack with pyinstxtractor, then decompile the entrypoint pyc (uncompyle6 / decompyle3). If PyArmor blocks static decompilation, switch to runtime: inject into the running process (pyinjector) and dump the code object (`_pyi_main_co`) from memory.
