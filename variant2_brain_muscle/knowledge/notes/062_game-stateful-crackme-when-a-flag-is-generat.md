---
tags: Game / stateful crackme
source: distilled/flareon
---
When a flag is generated FROM the correct end-state (player position, solved board, right input), forcing the win screen to render without actually reaching that state yields a WRONG flag — the state feeds the key. Drive the program to the genuine victory condition, or compute the key from the known target state and decode statically.
