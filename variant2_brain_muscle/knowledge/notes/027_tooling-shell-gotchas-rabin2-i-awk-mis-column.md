---
tags: Tooling / shell gotchas
source: distilled/playbook
---
rabin2 -i ... | awk mis-columns easily when demangled C++ names contain spaces — use rabin2 -ij (JSON) + python3/jq instead of guessing columns from text.
