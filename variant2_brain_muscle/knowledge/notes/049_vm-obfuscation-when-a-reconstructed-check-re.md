---
tags: VM / obfuscation
source: distilled/writeup
---
When a reconstructed check reduces to picking a SUBSET of table entries whose sums hit a target (and/or stay under a bound), model it as a MILP (PuLP + CBC), not Z3. Linear-sum subset constraints solve cleanly and fast as an integer program where Z3 chokes on the combinatorial search; map the chosen indices back to the input bitmask.
