---
tags: Parameters / arithmetic reasoning
source: distilled/playbook
---
If a transcription of an algorithm from bytecode keeps failing verification even though the core formula is measured and certain: stop hunting for the transcription bug — switch to a pure-data attack if you have enough samples (e.g. break an unknown-modulus LCG via GCD of consecutive differences, needs >=5-6 samples), then cross-check against an independent source in the challenge (e.g. a public key it already contains) — cross-verification beats "the formula looks right".
