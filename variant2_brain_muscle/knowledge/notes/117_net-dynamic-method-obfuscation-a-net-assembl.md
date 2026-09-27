---
tags: .NET dynamic-method obfuscation
source: distilled/flareon
---
A .NET assembly whose methods fail to decompile in dnSpy (IL looks like junk) and are each called inside a try/catch(InvalidProgramException) is hiding code as runtime-generated DynamicMethods. The catch handler rebuilds the real method: its IL is stored encrypted (often RC4) in EXTRA PE sections — watch for an abnormally high section count with VirtualSize < RawSize (real data then zero padding) — keyed/named by a per-method hash, with metadata tokens XOR-decoded and remapped via DynamicILInfo.GetTokenFor. Recover it either by patching the decrypted IL back statically, or by hooking the conversion routine to RETURN the finalized DynamicMethod object instead of invoking it, then dumping each method's IL.
