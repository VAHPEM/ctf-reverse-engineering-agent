---
tags: Web / HTML-JS crackme
source: distilled/writeup
---
An HTML/JS crackme's whole check is usually one function — read it directly instead of dynamic testing. Common shape: decode an embedded key (base64), then XOR it char-by-char against the password BEFORE its own decode. Recover the flag by replaying that XOR with the known-correct password; CyberChef does the base64+XOR chain in seconds.
