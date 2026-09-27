---
tags: Break circular key dependency
source: distilled/flareon
---
When the flag needs a key that is itself a hash of the decrypted flag (chicken-and-egg), look for a SEPARATE reversible check the binary performs on that same value — an XOR+Base64 comparison against a stored constant with a known key is invertible in CyberChef and hands you the value directly, no decryption loop required.
