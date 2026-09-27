---
tags: Firmware / UEFI
source: distilled/flareon
---
Identify unknown blobs by magic in a hex editor first: `_FVH` = UEFI firmware (FFS/firmware-volume), `FAT12` with leading bytes `EB 3F 90` = FAT12 disk image (open it directly with 7-Zip). Recognizing the container format often unlocks the whole challenge.
