---
tags: Parameters / arithmetic reasoning
source: distilled/playbook
---
Invert modexp mod 2^n (automorphism on odd numbers): save the LSB, force odd, raise to the inverse of e modulo lambda(2^n) (Carmichael, lambda(2^256)=2^254; phi(2^256)=2^255 works too), then restore the original LSB.
