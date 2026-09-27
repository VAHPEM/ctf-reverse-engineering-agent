---
tags: On-demand code decryption
source: distilled/flareon
---
IN/OUT port-I/O instructions in guest/hypervisor code cause VM exits; the host handler frequently RC4/xor-DECRYPTS the next function right before it runs and RE-ENCRYPTS it after (on the OUT). You can't get a fully-plaintext image statically — hook the exit handler or breakpoint the decrypt routine and dump each function while it is momentarily decrypted.
