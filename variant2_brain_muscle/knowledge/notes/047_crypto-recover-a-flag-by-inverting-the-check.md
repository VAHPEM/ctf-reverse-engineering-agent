---
tags: Crypto
source: distilled/writeup
---
Recover a flag by inverting the check on KNOWN-correct constants, not by searching inputs. If the code XOR/RC4/ChaCha-decrypts a stored blob only when input is right, the stored blob plus the recovered key already yields the flag statically — you rarely need to satisfy the live input path.
