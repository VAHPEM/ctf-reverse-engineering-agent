---
tags: Windows obf tooling
source: distilled/flareon
---
On an obfuscated Windows binary combine: FLOSS (`--only stack`/`--only decoded`) to pull stack and decoded strings that hold hidden commands/prompts; CAPA to fingerprint algorithms (MD5, Mersenne Twister, base64) despite obfuscation; and Time-Travel Debugging (tttracer.exe -> WinDbg) to record a full trace and query `dx @$cursession.TTD.Calls("mod!Func*")`, then step BACKWARD from an API call to recover the arguments and name-hashes that reached it.
