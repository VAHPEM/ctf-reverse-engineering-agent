---
tags: Input-sequence crackme
source: distilled/writeup
---
GUI challenges keyed on a gesture/sequence (a shake order like directions, or a fixed magic phrase) hide the expected sequence as a literal comparison inside one handler function. Find that function, read the expected order/string, and replay it — no need to reverse the surrounding UI.
