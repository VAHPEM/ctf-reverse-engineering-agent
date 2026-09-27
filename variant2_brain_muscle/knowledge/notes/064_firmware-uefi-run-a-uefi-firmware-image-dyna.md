---
tags: Firmware / UEFI
source: distilled/flareon
---
Run a UEFI firmware image dynamically in QEMU with OVMF: `qemu-system-x86_64 -bios <fw>.bin -drive format=raw,file=<disk>.img`. Then explore its shell (`map -r`, `fs0:`, `ls`, `help`) to discover custom commands the challenge added.
