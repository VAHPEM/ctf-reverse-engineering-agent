---
tags: Qt / GUI crackme
source: distilled/playbook
---
Qt app with direct input (QLineEdit): breakpoint a Qt API the handler surely calls (e.g. QLineEdit::setText) to locate the handler — faster/surer than chasing connect()/constructor via static xrefs (two empty xrefs in a row = switch your anchor point).
