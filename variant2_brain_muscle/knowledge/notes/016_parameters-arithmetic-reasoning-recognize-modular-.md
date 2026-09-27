---
tags: Parameters / arithmetic reasoning
source: distilled/playbook
---
Recognize "modular exponentiation mod 2^n": compiler-generated 128-bit divide (__udivti3/__umodti3) called repeatedly, interleaved with accumulating mul/imul -> signature of square-and-multiply for a bignum modexp, NOT matrix multiplication just because of nested loops.
