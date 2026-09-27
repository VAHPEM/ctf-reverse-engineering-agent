---
tags: Qt / GUI crackme
source: distilled/playbook
---
Indirect calls of the form DAT_global + constant -> called repeatedly with NO branch on user input: usually just obfuscation wrapping ordinary app-init code, not the check logic — prefer finding the real UI event handler.
