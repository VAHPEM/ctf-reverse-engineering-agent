---
tags: Repair corrupt / truncated PE
source: distilled/flareon
---
A truncated or corrupt packed PE (upx -d errors, Windows refuses to load) is still analyzable: append NULL bytes until the file reaches the header's stated PE size so `upx -d` succeeds, OR in CFF Explorer remove the truncated section (.rsrc) and zero the affected data directories (import/resource/reloc), then re-add missing import MODULE names inferred from the imported function names. If it crashes in the unpack stub during import resolution, dump the already-decompressed code from memory.
