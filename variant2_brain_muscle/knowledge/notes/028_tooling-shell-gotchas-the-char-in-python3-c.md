---
tags: Tooling / shell gotchas
source: distilled/playbook
---
The '!' char in python3 -c "..." can be eaten by bash/zsh history expansion, causing confusing errors — write the script to a file via a quoted heredoc (<< 'EOF') and run python3 file.py; avoid -c when special chars are involved.
