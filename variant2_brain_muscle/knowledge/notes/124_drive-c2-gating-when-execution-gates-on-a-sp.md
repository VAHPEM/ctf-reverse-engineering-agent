---
tags: Drive C2 gating
source: distilled/flareon
---
When execution gates on a specific C2 reply, feed it with FakeNet-NG's custom TcpRawFile response (or netcat / an interposing proxy) so the sample proceeds down the real path; it may additionally require a specific module filename (it compares GetModuleFileName to e.g. Spell.EXE) — rename your copy to match, or set the env/registry state it checks.
