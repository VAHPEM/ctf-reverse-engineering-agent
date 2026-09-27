---
tags: Python / bytecode
source: distilled/playbook
---
Python decompiler doesn't support the compile version (e.g. Python 3.12+, decompyle3/uncompyle6 say "unsupported version"): use pydisasm (the xdis package) to read the bytecode directly instead of forcing a decompiler.
