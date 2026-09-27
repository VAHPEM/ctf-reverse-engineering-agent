---
tags: Web / HTML-JS crackme
source: distilled/writeup
---
A multi-MB obfuscated HTML/JS file is mostly garbage with a few live lines. Reduce it: keep only lines that reference the handful of relevant identifiers, and grow the keep-set as you discover each `X = ...` assignment. The signal collapses to a readable core once the jQuery-test / dead noise is dropped.
