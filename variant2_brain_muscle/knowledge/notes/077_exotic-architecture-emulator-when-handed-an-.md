---
tags: Exotic architecture / emulator
source: distilled/flareon
---
When handed an emulator config plus a disk/tape image for an old system (e.g. PDP-11/2.11BSD via SIMH), read the CONFIG FILE first — it names the devices/disks and how to attach them. You often need not solve it live: old container formats (.tap tape, `compress` .Z) are documented and extractable statically.
