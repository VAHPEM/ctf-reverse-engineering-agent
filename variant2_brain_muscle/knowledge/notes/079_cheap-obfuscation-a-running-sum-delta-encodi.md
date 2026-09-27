---
tags: Cheap obfuscation
source: distilled/flareon
---
A running-sum 'delta encoding' (each output byte = previous decoded byte + next input byte) is a trivial obfuscation used to defeat known-plaintext guessing. Recognize the accumulator pattern and undo it with a simple prefix subtraction.
