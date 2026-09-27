---
tags: Managed / MonoGame
source: distilled/flareon
---
For a MonoGame or .NET game, the real logic and all strings live in the accompanying `<Name>.dll`, not the launcher `.exe`. Decompile the DLL (dotPeek/dnSpy) and grep the DLL's strings for the flag or `@flare-on.com` before reversing anything.
