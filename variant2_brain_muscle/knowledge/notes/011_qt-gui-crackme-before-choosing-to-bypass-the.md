---
tags: Qt / GUI crackme
source: distilled/playbook
---
Before choosing to "bypass the condition" (patch the return, brute one branch), always ask: "is the flag COMPUTED from the valid input, or does it only depend on the input making a check pass/fail?" — bypassing is valid only once you've confirmed no later step reuses the real input as a key/seed.
