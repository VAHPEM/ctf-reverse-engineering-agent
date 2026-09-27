---
tags: Input-sequence crackme
source: distilled/writeup
---
'Your input + fixed data, added byte-by-byte, is then EXECUTED as code' challenges: pick the simplest valid target code and solve for the input that produces it. E.g. to make the region a single `ret` (0xC3), choose input bytes so each sum lands on 0xC3; the resulting input is the accepted answer.
