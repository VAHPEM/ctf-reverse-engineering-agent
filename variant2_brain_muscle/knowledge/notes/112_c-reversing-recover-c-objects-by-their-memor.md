---
tags: C++ reversing
source: distilled/flareon
---
Recover C++ objects by their memory layout. A vftable is a run of function pointers (IDA annotates its start) — define it as a struct and apply it so virtual calls become named. A std::string/std::wstring is {offset 0: inline buffer for short strings OR a heap pointer, next field: length, next: capacity}. Allocate size (the `new` argument) tells you the object size for the struct. Use `capa -vv` or the capa-explorer IDA plugin to jump straight to the base64/RC4/MD5 routines instead of reading every function.
