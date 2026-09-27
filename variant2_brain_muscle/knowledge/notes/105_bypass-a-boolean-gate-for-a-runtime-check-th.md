---
tags: Bypass a boolean gate
source: distilled/flareon
---
For a runtime check that returns a True/False (anti-cheat, license, password verify), breakpoint the compare and flip the returned register value in a debugger (x64dbg) — usually faster than reversing the whole condition.
