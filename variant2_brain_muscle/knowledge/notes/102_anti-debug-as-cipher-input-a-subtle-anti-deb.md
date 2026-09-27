---
tags: Anti-debug as cipher input
source: distilled/flareon
---
A subtle anti-debug uses the PEB BeingDebugged flag AS the value zero inside a cipher/computation: under a debugger the flag is 1, so derived numbers are subtly wrong and decryption silently fails even with the correct key. Force the flag to 0 (or run without a debugger) rather than trusting the live value.
