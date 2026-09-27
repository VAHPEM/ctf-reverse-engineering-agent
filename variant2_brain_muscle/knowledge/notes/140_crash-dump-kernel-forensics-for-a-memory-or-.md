---
tags: Crash-dump / kernel forensics
source: distilled/flareon
---
For a memory or crash dump, drive WinDbg: `!analyze -v` for the bugcheck, `!process`/`k` for context, walk the DRIVER_OBJECT (it holds the driver PE's base, size and DriverInit entry point) and `.writemem` to carve drivers out of memory. Find a rootkit's hidden pool allocations by its tag with `!poolfind <tag>` (e.g. ExAllocatePoolWithTag tag 'FLAR'); `!object` lists DRIVER_OBJECTs, including ones the rootkit created for injected payloads.
