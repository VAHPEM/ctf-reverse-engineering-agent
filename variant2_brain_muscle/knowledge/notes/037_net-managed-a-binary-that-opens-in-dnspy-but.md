---
tags: .NET / managed
source: distilled/writeup
---
A binary that opens in dnSpy but has native interop is often Managed C++, not C#. `Main` may be hidden in a synthetic namespace (e.g. named `-`) inside the `<Module>` type, not in a `Program`/`Form` class. Search all types for the entry point instead of trusting the obvious locations.
