---
tags: Tooling / shell gotchas
source: distilled/playbook
---
When one task needs both (a) bulk-extracting a large amount of structured data (every entry of a big table, every case of a huge switch) AND (b) computing something from it (a graph search, a solve), do NOT do both in one author_and_run script — a script that big can exceed the output-token ceiling and get cut off mid-generation (truncated -> syntax error, or silently no output if the final print() never got written). Split into two calls: first extract the raw data to a file (JSON/pickle) with a print() confirming its size; then a second, smaller script loads that file and does the analysis.
